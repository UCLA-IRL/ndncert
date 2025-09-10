/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2025, Regents of the University of California.
 *
 * This file is part of ndncert, a certificate management system based on NDN.
 *
 * ndncert is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ndncert is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ndncert, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndncert authors and contributors.
 */

#include "challenge-dns.hpp"
#include "detail/crypto-helpers.hpp"

#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/sha256.hpp>

#include <regex>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <cstring>
#include <netdb.h>

namespace ndncert {

NDN_LOG_INIT(ndncert.challenge.dns);
NDNCERT_REGISTER_CHALLENGE(ChallengeDns, "dns");

const std::string ChallengeDns::NEED_DOMAIN = "need-domain";
const std::string ChallengeDns::NEED_RECORD = "need-record";  
const std::string ChallengeDns::WRONG_RECORD = "wrong-record";
const std::string ChallengeDns::READY_FOR_VALIDATION = "ready-for-validation";
const std::string ChallengeDns::PARAMETER_KEY_DOMAIN = "domain";
const std::string ChallengeDns::PARAMETER_KEY_CONFIRMATION = "confirmation";
const std::string ChallengeDns::DNS_PREFIX = "_ndncert-challenge";

ChallengeDns::ChallengeDns(const size_t& maxAttemptTimes,
                           const time::seconds secretLifetime)
  : ChallengeModule("dns", maxAttemptTimes, secretLifetime)
{
}

// For CA
std::tuple<ErrorCode, std::string>
ChallengeDns::handleChallengeRequest(const Block& params, ca::RequestState& request)
{
  params.parse();
  auto currentTime = time::system_clock::now();

  if (request.status == Status::BEFORE_CHALLENGE) {
    // First request: requester provides domain name
    std::string domain = readString(params.get(tlv::ParameterValue));
    
    if (!isValidDomainName(domain)) {
      NDN_LOG_TRACE("Invalid domain name: " << domain);
      return returnWithError(request, ErrorCode::INVALID_PARAMETER, "Invalid domain name");
    }

    // Generate challenge token
    std::string challengeToken = generateSecretCode();
    
    // Compute key hash from requester's public key
    auto keyBits = request.cert.getPublicKey();
    ndn::util::Sha256 sha256;
    sha256.update(keyBits);
    std::string keyHash = sha256.toString();

    // Compute expected DNS record value
    std::string expectedValue = computeChallengeResponse(challengeToken, keyHash);
    
    JsonSection secretJson;
    secretJson.add("token", challengeToken);
    secretJson.add("domain", domain);
    secretJson.add("key-hash", keyHash);
    secretJson.add("expected-value", expectedValue);
    secretJson.add("record-name", getDnsRecordName(domain));

    NDN_LOG_TRACE("DNS challenge for request " << ndn::toHex(request.requestId) 
                  << " domain=" << domain << " token=" << challengeToken);

    return returnWithNewChallengeStatus(request, NEED_RECORD, std::move(secretJson),
                                        m_maxAttemptTimes, m_secretLifetime);
  }

  if (request.challengeState) {
    auto secret = request.challengeState->secrets;
    auto challengeStatus = request.challengeState->challengeStatus;

    // Check if challenge has expired
    if (currentTime - request.challengeState->timestamp >= m_secretLifetime) {
      NDN_LOG_TRACE("Challenge expired");
      return returnWithError(request, ErrorCode::OUT_OF_TIME, "Challenge expired.");
    }

    if (challengeStatus == NEED_RECORD) {
      // Requester confirms they've created the DNS record
      static const std::string READY_CONFIRMATION = "ready";
      std::string confirmation = readString(params.get(tlv::ParameterValue));
      if (confirmation != READY_CONFIRMATION) {
        return returnWithError(request, ErrorCode::INVALID_PARAMETER, 
                              "Expected '" + READY_CONFIRMATION + "' confirmation");
      }

      // Move to validation phase
      auto remainTime = getRemainingTime(currentTime, request.challengeState->timestamp);
      return returnWithNewChallengeStatus(request, READY_FOR_VALIDATION, std::move(secret),
                                          request.challengeState->remainingTries, remainTime);
    }
    else if (challengeStatus == READY_FOR_VALIDATION || challengeStatus == WRONG_RECORD) {
      // Perform DNS verification
      std::string domain = secret.get<std::string>("domain");
      std::string expectedValue = secret.get<std::string>("expected-value");

      if (verifyDnsRecord(domain, expectedValue)) {
        NDN_LOG_TRACE("DNS verification successful for domain " << domain);
        return returnWithSuccess(request);
      }
      else {
        // DNS verification failed
        if (request.challengeState->remainingTries > 1) {
          auto remainTime = getRemainingTime(currentTime, request.challengeState->timestamp);
          NDN_LOG_TRACE("DNS verification failed, remaining tries = " 
                        << request.challengeState->remainingTries - 1);
          return returnWithNewChallengeStatus(request, WRONG_RECORD, std::move(secret),
                                              request.challengeState->remainingTries - 1, remainTime);
        }
        else {
          NDN_LOG_TRACE("DNS verification failed, no tries remaining");
          return returnWithError(request, ErrorCode::OUT_OF_TRIES, 
                                "DNS verification failed. No tries remaining.");
        }
      }
    }
  }

  return returnWithError(request, ErrorCode::INVALID_PARAMETER, "Unexpected challenge status.");
}

// For Client
std::multimap<std::string, std::string>
ChallengeDns::getRequestedParameterList(Status status, const std::string& challengeStatus)
{
  std::multimap<std::string, std::string> result;
  
  if (status == Status::BEFORE_CHALLENGE && challengeStatus.empty()) {
    result.emplace(PARAMETER_KEY_DOMAIN, "Please input the domain name you want to validate");
  }
  else if (status == Status::CHALLENGE && challengeStatus == NEED_RECORD) {
    result.emplace(PARAMETER_KEY_CONFIRMATION, 
                  "Create the DNS TXT record as instructed, then enter 'ready' to proceed");
  }
  else if (status == Status::CHALLENGE && challengeStatus == READY_FOR_VALIDATION) {
    // Automatic DNS verification phase - no user input needed
  }
  else if (status == Status::CHALLENGE && challengeStatus == WRONG_RECORD) {
    result.emplace(PARAMETER_KEY_CONFIRMATION, 
                  "DNS record verification failed. Please check the record and enter 'ready' to retry");
  }
  else {
    NDN_THROW(std::runtime_error("Unexpected challenge status"));
  }
  
  return result;
}

Block
ChallengeDns::genChallengeRequestTLV(Status status, const std::string& challengeStatus,
                                     const std::multimap<std::string, std::string>& params)
{
  Block request(tlv::EncryptedPayload);
  
  if (status == Status::BEFORE_CHALLENGE) {
    auto paramValue = validateSingleParameter(params, PARAMETER_KEY_DOMAIN);
    request.push_back(ndn::makeStringBlock(tlv::SelectedChallenge, CHALLENGE_TYPE));
    request.push_back(ndn::makeStringBlock(tlv::ParameterKey, PARAMETER_KEY_DOMAIN));
    request.push_back(ndn::makeStringBlock(tlv::ParameterValue, paramValue));
  }
  else if (status == Status::CHALLENGE && 
           (challengeStatus == NEED_RECORD || challengeStatus == WRONG_RECORD)) {
    auto paramValue = validateSingleParameter(params, PARAMETER_KEY_CONFIRMATION);
    request.push_back(ndn::makeStringBlock(tlv::SelectedChallenge, CHALLENGE_TYPE));
    request.push_back(ndn::makeStringBlock(tlv::ParameterKey, PARAMETER_KEY_CONFIRMATION));
    request.push_back(ndn::makeStringBlock(tlv::ParameterValue, paramValue));
  }
  else if (status == Status::CHALLENGE && challengeStatus == READY_FOR_VALIDATION) {
    // Automatic verification - send challenge type only
    request.push_back(ndn::makeStringBlock(tlv::SelectedChallenge, CHALLENGE_TYPE));
    request.push_back(ndn::makeStringBlock(tlv::ParameterKey, "verify"));
    request.push_back(ndn::makeStringBlock(tlv::ParameterValue, "now"));
  }
  else {
    NDN_THROW(std::runtime_error("Unexpected challenge status"));
  }
  
  request.encode();
  return request;
}

bool
ChallengeDns::isValidDomainName(const std::string& domain)
{
  if (domain.empty() || domain.length() > 253) {
    return false;
  }

  static const std::regex domainPattern = [] {
    return std::regex(R"_RE_((^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$))_RE_");
  }();
  
  return std::regex_match(domain, domainPattern);
}

std::string
ChallengeDns::computeChallengeResponse(const std::string& token, const std::string& keyHash)
{
  std::string input = token + "." + keyHash;
  ndn::util::Sha256 sha256;
  sha256 << input;
  return sha256.toString();
}

time::seconds
ChallengeDns::getRemainingTime(const time::system_clock::time_point& currentTime,
                               const time::system_clock::time_point& startTime) const
{
  auto elapsed = currentTime - startTime;
  auto remaining = m_secretLifetime - elapsed;
  return time::duration_cast<time::seconds>(remaining);
}

std::string
ChallengeDns::validateSingleParameter(const std::multimap<std::string, std::string>& params,
                                      const std::string& expectedKey) const
{
  if (params.size() != 1 || params.find(expectedKey) == params.end()) {
    NDN_THROW(std::runtime_error("Wrong parameter provided"));
  }
  return params.find(expectedKey)->second;
}

std::string
ChallengeDns::getDnsRecordName(const std::string& domain) const
{
  return DNS_PREFIX + "." + domain;
}

bool
ChallengeDns::verifyDnsRecord(const std::string& domain, const std::string& expectedValue) const
{
  std::string recordName = getDnsRecordName(domain);
  
  // Initialize resolver
  if (res_init() != 0) {
    NDN_LOG_ERROR("Failed to initialize resolver");
    return false;
  }

  // Query buffer
  unsigned char answer[4096];
  
  // Perform DNS TXT query
  int answerLen = res_query(recordName.c_str(), C_IN, T_TXT, answer, sizeof(answer));
  if (answerLen < 0) {
    NDN_LOG_TRACE("DNS query failed for " << recordName << " (h_errno=" << h_errno << ")");
    return false;
  }

  // Parse DNS response
  HEADER* header = reinterpret_cast<HEADER*>(answer);
  if (header->rcode != NOERROR) {
    NDN_LOG_TRACE("DNS query returned error code: " << header->rcode);
    return false;
  }

  if (ntohs(header->ancount) == 0) {
    NDN_LOG_TRACE("No TXT records found for " << recordName);
    return false;
  }

  // Skip DNS header and question section
  unsigned char* ptr = answer + sizeof(HEADER);
  unsigned char* endPtr = answer + answerLen;

  // Skip question section
  for (int i = 0; i < ntohs(header->qdcount) && ptr < endPtr; i++) {
    // Skip QNAME
    while (ptr < endPtr && *ptr != 0) {
      if ((*ptr & 0xC0) == 0xC0) {
        ptr += 2; // Compressed name
        break;
      }
      else {
        ptr += *ptr + 1; // Label length + label
      }
    }
    if (ptr < endPtr && *ptr == 0) ptr++; // Skip null terminator
    ptr += 4; // Skip QTYPE and QCLASS
  }

  // Parse answer section
  for (int i = 0; i < ntohs(header->ancount) && ptr < endPtr; i++) {
    // Skip NAME field
    if ((*ptr & 0xC0) == 0xC0) {
      ptr += 2; // Compressed name
    }
    else {
      while (ptr < endPtr && *ptr != 0) {
        ptr += *ptr + 1;
      }
      if (ptr < endPtr) ptr++; // Skip null terminator
    }

    if (ptr + 10 > endPtr) break; // Not enough data for TYPE, CLASS, TTL, RDLENGTH

    uint16_t type = ntohs(*(uint16_t*)ptr);
    ptr += 2;
    uint16_t class_ = ntohs(*(uint16_t*)ptr);
    ptr += 2;
    ptr += 4; // Skip TTL
    uint16_t rdlength = ntohs(*(uint16_t*)ptr);
    ptr += 2;

    if (ptr + rdlength > endPtr) break; // Not enough data for RDATA

    if (type == T_TXT && class_ == C_IN) {
      // Parse TXT record data
      unsigned char* txtEnd = ptr + rdlength;
      while (ptr < txtEnd) {
        uint8_t txtLen = *ptr++;
        if (ptr + txtLen > txtEnd) break;
        
        std::string txtValue(reinterpret_cast<char*>(ptr), txtLen);
        NDN_LOG_TRACE("Found TXT record: " << txtValue);
        
        if (txtValue == expectedValue) {
          NDN_LOG_TRACE("DNS TXT record matches expected value");
          return true;
        }
        
        ptr += txtLen;
      }
    }
    else {
      ptr += rdlength; // Skip non-TXT records
    }
  }

  NDN_LOG_TRACE("Expected TXT value not found in DNS response");
  return false;
}

} // namespace ndncert
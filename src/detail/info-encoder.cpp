/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2024, Regents of the University of California.
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

#include "detail/info-encoder.hpp"

namespace ndncert::infotlv {

Block
encodeDataContent(const CaProfile& caConfig, const Certificate& certificate)
{
  Block content(ndn::tlv::Content);
  content.push_back(makeNestedBlock(tlv::CaPrefix, caConfig.caPrefix));
  std::string caInfo;
  if (caConfig.caInfo.empty()) {
    caInfo = "Issued by " + certificate.getSignatureInfo().getKeyLocator().getName().toUri();
  }
  else {
    caInfo = caConfig.caInfo;
  }
  content.push_back(ndn::makeStringBlock(tlv::CaInfo, caInfo));
  for (const auto& key : caConfig.probeParameterKeys) {
    content.push_back(ndn::makeStringBlock(tlv::ParameterKey, key));
  }
  content.push_back(ndn::makeNonNegativeIntegerBlock(tlv::MaxValidityPeriod, caConfig.maxValidityPeriod.count()));
  content.push_back(makeNestedBlock(tlv::CaCertificate, certificate));
  content.encode();
  return content;
}

CaProfile
decodeDataContent(const Block& block)
{
  CaProfile result;
  block.parse();
  for (auto const &item : block.elements()) {
    switch (item.type()) {
      case tlv::CaPrefix:
        item.parse();
        result.caPrefix.wireDecode(item.get(ndn::tlv::Name));
        break;
      case tlv::CaInfo:
        result.caInfo = readString(item);
        break;
      case tlv::ParameterKey:
        result.probeParameterKeys.push_back(readString(item));
        break;
      case tlv::MaxValidityPeriod:
        result.maxValidityPeriod = time::seconds(readNonNegativeInteger(item));
        break;
      case tlv::CaCertificate:
        item.parse();
        result.cert = std::make_shared<Certificate>(item.get(ndn::tlv::Data));
        break;
      default:
        if (ndn::tlv::isCriticalType(item.type())) {
          NDN_THROW(std::runtime_error("Unrecognized TLV Type: " + std::to_string(item.type())));
        }
        break;
    }
  }
  return result;
}

} // namespace ndncert::infotlv

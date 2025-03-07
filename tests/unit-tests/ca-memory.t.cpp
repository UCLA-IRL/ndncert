/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2021, Regents of the University of California.
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

#include "detail/ca-memory.hpp"
#include "detail/ca-sqlite.hpp"
#include "test-common.hpp"

namespace ndncert {
namespace tests {

using namespace ca;

BOOST_FIXTURE_TEST_SUITE(TestCaMemory, IdentityManagementFixture)

BOOST_AUTO_TEST_CASE(RequestOperations)
{
  CaMemory storage;

  auto identity1 = addIdentity(Name("/ndn/site1"));
  auto key1 = identity1.getDefaultKey();
  auto cert1 = key1.getDefaultCertificate();

  // add operation
  RequestId requestId = {{101}};
  RequestState request1;
  request1.caPrefix = Name("/ndn/site1");
  request1.requestId = requestId;
  request1.requestType = RequestType::NEW;
  request1.cert = cert1;
  BOOST_CHECK_NO_THROW(storage.addRequest(request1));

  // get operation
  auto result = storage.getRequest(requestId);
  BOOST_CHECK_EQUAL(request1.cert, result.cert);
  BOOST_CHECK(request1.status == result.status);
  BOOST_CHECK_EQUAL(request1.caPrefix, result.caPrefix);
  BOOST_CHECK_EQUAL_COLLECTIONS(request1.encryptionKey.begin(), request1.encryptionKey.end(),
                                result.encryptionKey.begin(), result.encryptionKey.end());

  // update operation
  RequestState request2;
  request2.caPrefix = Name("/ndn/site1");
  request2.requestId = requestId;
  request2.requestType = RequestType::NEW;
  request2.cert = cert1;
  request2.challengeType = "email";
  JsonSection secret;
  secret.add("code", "1234");
  request2.challengeState = ChallengeState("test", time::system_clock::now(), 3,
                                           time::seconds(3600), std::move(secret));
  storage.updateRequest(request2);
  result = storage.getRequest(requestId);
  BOOST_CHECK_EQUAL(request2.cert, result.cert);
  BOOST_CHECK(request2.status == result.status);
  BOOST_CHECK_EQUAL(request2.caPrefix, result.caPrefix);

  // another add operation
  auto identity2 = addIdentity(Name("/ndn/site2"));
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();
  RequestId requestId2 = {{102}};
  RequestState request3;
  request3.caPrefix = Name("/ndn/site2");
  request3.requestId = requestId2;
  request3.requestType = RequestType::NEW;
  request3.cert = cert2;
  storage.addRequest(request3);

  // list operation
  auto allRequests = storage.listAllRequests();
  BOOST_CHECK_EQUAL(allRequests.size(), 2);

  storage.deleteRequest(requestId2);
  allRequests = storage.listAllRequests();
  BOOST_CHECK_EQUAL(allRequests.size(), 1);
}

BOOST_AUTO_TEST_SUITE_END() // TestCaMemory

} // namespace tests
} // namespace ndncert

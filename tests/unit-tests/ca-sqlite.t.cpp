/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2020, Regents of the University of California.
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

#include "detail/ca-sqlite.hpp"
#include "test-common.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

using namespace ca;

BOOST_FIXTURE_TEST_SUITE(TestCaSqlite, DatabaseFixture)

BOOST_AUTO_TEST_CASE(RequestOperations)
{
  CaSqlite storage(Name(), dbDir.string() + "/TestCaSqlite_RequestOperations.db");

  auto identity1 = addIdentity(Name("/ndn/site1"));
  auto key1 = identity1.getDefaultKey();
  auto cert1 = key1.getDefaultCertificate();

  // add operation
  RequestId requestId = {{1,2,3,4,5,6,7,8}};
  std::array<uint8_t, 16> aesKey1;
  RequestState request1(Name("/ndn/site1"), requestId, RequestType::NEW, Status::BEFORE_CHALLENGE, cert1, std::move(aesKey1));
  storage.addRequest(request1);

  // get operation
  auto result = storage.getRequest(requestId);
  BOOST_CHECK_EQUAL(request1.cert, result.cert);
  BOOST_CHECK(request1.status == result.status);
  BOOST_CHECK_EQUAL(request1.caPrefix, result.caPrefix);
  BOOST_CHECK_EQUAL_COLLECTIONS(request1.encryptionKey.begin(), request1.encryptionKey.end(),
                                result.encryptionKey.begin(), result.encryptionKey.end());

  // update operation
  JsonSection json;
  json.put("test", "4567");
  std::array<uint8_t, 16> aesKey2;
  RequestState request2(Name("/ndn/site1"), requestId, RequestType::NEW, Status::CHALLENGE, cert1,
                   "email", "test", time::system_clock::now(), 3, time::seconds(3600),
                  std::move(json), std::move(aesKey2), 0);
  storage.updateRequest(request2);
  result = storage.getRequest(requestId);
  BOOST_CHECK_EQUAL(request2.cert, result.cert);
  BOOST_CHECK(request2.status == result.status);
  BOOST_CHECK_EQUAL(request2.caPrefix, result.caPrefix);

  auto identity2 = addIdentity(Name("/ndn/site2"));
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();
  RequestId requestId2 = {{8,7,6,5,4,3,2,1}};
  std::array<uint8_t, 16> aesKey3;
  RequestState request3(Name("/ndn/site2"), requestId2, RequestType::NEW,
                        Status::BEFORE_CHALLENGE, cert2, std::move(aesKey3));
  storage.addRequest(request3);

  // list operation
  auto allRequests = storage.listAllRequests();
  BOOST_CHECK_EQUAL(allRequests.size(), 2);

  storage.deleteRequest(requestId2);
  allRequests = storage.listAllRequests();
  BOOST_CHECK_EQUAL(allRequests.size(), 1);

  storage.deleteRequest(requestId);
  allRequests = storage.listAllRequests();
  BOOST_CHECK_EQUAL(allRequests.size(), 0);
}

BOOST_AUTO_TEST_CASE(DuplicateAdd)
{
    CaSqlite storage(Name(), dbDir.string() + "/TestCaSqlite_DuplicateAdd.db");

    auto identity1 = addIdentity(Name("/ndn/site1"));
    auto key1 = identity1.getDefaultKey();
    auto cert1 = key1.getDefaultCertificate();

    // add operation
    RequestId requestId = {{1,2,3,4,5,6,7,8}};
    std::array<uint8_t, 16> aesKey;
    RequestState request1(Name("/ndn/site1"),requestId, RequestType::NEW,
                          Status::BEFORE_CHALLENGE, cert1, std::move(aesKey));
    BOOST_CHECK_NO_THROW(storage.addRequest(request1));
    // add again
    BOOST_CHECK_THROW(storage.addRequest(request1), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END() // TestCaModule

} // namespace tests
} // namespace ndncert
} // namespace ndn

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2021 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

#ifndef NDNCERT_TESTS_DATABASE_FIXTURE_HPP
#define NDNCERT_TESTS_DATABASE_FIXTURE_HPP

#include "identity-management-fixture.hpp"
#include "unit-test-time-fixture.hpp"

#include <boost/filesystem.hpp>

namespace ndncert {
namespace tests {

class IdentityManagementTimeFixture : public UnitTestTimeFixture
                                    , public IdentityManagementFixture
{
};

class DatabaseFixture : public IdentityManagementTimeFixture
{
public:
  DatabaseFixture()
  {
    boost::filesystem::path parentDir{TMP_TESTS_PATH};
    dbDir = parentDir / "test-home" / ".ndncert";
    if (!boost::filesystem::exists(dbDir)) {
      boost::filesystem::create_directory(dbDir);
    }
  }

  ~DatabaseFixture()
  {
    boost::filesystem::remove_all(dbDir);
  }

protected:
  boost::filesystem::path dbDir;
};

} // namespace tests
} // namespace ndncert

#endif // NDNCERT_TESTS_DATABASE_FIXTURE_HPP

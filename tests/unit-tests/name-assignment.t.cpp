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

#include "name-assignment/assignment-inst-email.hpp"
#include "name-assignment/assignment-random.hpp"
#include "name-assignment/assignment-param.hpp"
#include "name-assignment/assignment-hash.hpp"
#include "test-common.hpp"

namespace ndncert {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestNameAssignment)

BOOST_AUTO_TEST_CASE(NameAssignmentRandom)
{
  AssignmentRandom assignment;
  BOOST_CHECK_EQUAL(assignment.assignName(std::multimap<std::string, std::string>()).size(), 1);
  BOOST_CHECK_EQUAL(assignment.assignName(std::multimap<std::string, std::string>()).begin()->size(), 1);
}

BOOST_AUTO_TEST_CASE(NameAssignmentParam)
{
  AssignmentParam assignment("/abc/xyz");
  std::multimap<std::string, std::string> params;
  params.emplace("abc", "123");
  BOOST_CHECK_EQUAL(assignment.assignName(params).size(), 0);
  params.emplace("xyz", "789");
  BOOST_CHECK_EQUAL(assignment.assignName(params).size(), 1);
  BOOST_CHECK_EQUAL(*assignment.assignName(params).begin(), Name("/123/789"));
  params.emplace("fake", "456");
  BOOST_CHECK_EQUAL(assignment.assignName(params).size(), 1);
  BOOST_CHECK_EQUAL(*assignment.assignName(params).begin(), Name("/123/789"));
  params.find("xyz")->second = "";
  BOOST_CHECK_EQUAL(assignment.assignName(params).size(), 0);

  AssignmentParam assignment2("/\"guest\"/email");
  params.emplace("email", "1@1.com");
  BOOST_CHECK_EQUAL(assignment2.assignName(params).size(), 1);
  BOOST_CHECK_EQUAL(assignment2.assignName(params).begin()->toUri(), Name("/guest/1@1.com").toUri());

  AssignmentParam assignment3("/\"/email");
  BOOST_CHECK_EQUAL(assignment3.assignName(params).size(), 0);
}

BOOST_AUTO_TEST_CASE(NameAssignmentHash)
{
  AssignmentHash assignment("/abc/xyz");
  std::multimap<std::string, std::string> params;
  params.emplace("abc", "123");
  BOOST_CHECK_EQUAL(assignment.assignName(params).size(), 0);
  params.emplace("xyz", "789");
  BOOST_CHECK_EQUAL(assignment.assignName(params).size(), 1);
  BOOST_CHECK_EQUAL(assignment.assignName(params).begin()->size(), 2);
  params.emplace("fake", "456");
  BOOST_CHECK_EQUAL(assignment.assignName(params).size(), 1);
  BOOST_CHECK_EQUAL(assignment.assignName(params).begin()->size(), 2);
  params.find("xyz")->second = "";
  BOOST_CHECK_EQUAL(assignment.assignName(params).size(), 1);
  BOOST_CHECK_EQUAL(assignment.assignName(params).begin()->size(), 2);
}

BOOST_AUTO_TEST_CASE(NameAssignmentInstEmail)
{
  AssignmentInstEmail assignment("cs.ucla.edu");
  std::multimap<std::string, std::string> params;
  BOOST_CHECK_EQUAL(assignment.assignName(params).size(), 0);
  params.emplace("email", "das@math.ucla.edu");
  BOOST_CHECK_EQUAL(assignment.assignName(params).size(), 0);

  params.clear();
  params.emplace("email", "das@cs.ucla.edu");
  BOOST_CHECK_EQUAL(assignment.assignName(params).size(), 1);
  BOOST_CHECK_EQUAL(*assignment.assignName(params).begin(), Name("/das"));
}

BOOST_AUTO_TEST_SUITE_END() // TestNameAssignment

} // namespace tests
} // namespace ndncert

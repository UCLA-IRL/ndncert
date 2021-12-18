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

#include "assignment-inst-email.hpp"

namespace ndncert {

NDN_LOG_INIT(ndncert.name-assignment.assignmentInstEmail);

NDNCERT_REGISTER_FUNCFACTORY(AssignmentInstEmail, "inst-email");

AssignmentInstEmail::AssignmentInstEmail(const std::string& format)
  : NameAssignmentFunc(format)
{
  if (m_nameFormat.size() != 1) {
    NDN_LOG_WARN("Slash in the institution domain name. May cause undefined behaviors. ");
  }
}

std::vector<ndn::PartialName>
AssignmentInstEmail::assignName(const std::multimap<std::string, std::string>& params)
{
  std::vector<ndn::PartialName> resultList;
  Name result;
  if (!m_nameFormat.empty() && params.count("email") > 0) {
    const std::string& email = params.begin()->second;
    const std::string& domain = m_nameFormat.at(0);
    if (email.substr(email.size() - domain.size() - 1, domain.size() + 1) == "@" + domain) {
      result.push_back(email.substr(0, email.size() - domain.size() - 1));
      resultList.push_back(std::move(result));
    }
  }
  return resultList;
}

} // namespace ndncert

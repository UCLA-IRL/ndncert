/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2022, Regents of the University of California.
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

#include "assignment-email.hpp"

namespace ndncert {

NDNCERT_REGISTER_FUNCFACTORY(AssignmentEmail, "email");

AssignmentEmail::AssignmentEmail(const std::string& format)
  : NameAssignmentFunc(format)
{
}

std::vector<ndn::PartialName>
AssignmentEmail::assignName(const std::multimap<std::string, std::string>& params)
{
  std::vector<ndn::PartialName> resultList;
  Name result;
  if (!m_nameFormat.empty() && params.count("email") > 0) {
    const std::string& email = params.begin()->second;
    auto formatIter = m_nameFormat.begin();
    size_t emailSplit = email.rfind("@");
    std::string domain = "." + email.substr(emailSplit + 1);

    if (emailSplit != std::string::npos && emailSplit > 0) {
      size_t domainSplit = domain.rfind(".");
      while (domainSplit != std::string::npos) {
        if (formatIter != m_nameFormat.end() && domain.substr(domainSplit + 1) == *formatIter) {
          formatIter++;
        }
        else {
          result.push_back(domain.substr(domainSplit + 1).c_str());
        }
        domain = domain.substr(0, domainSplit);
        domainSplit = domain.rfind(".");
      }
      result.push_back(email.substr(0, emailSplit).c_str());
      resultList.push_back(std::move(result));
    }
  }
  return resultList;
}

} // namespace ndncert

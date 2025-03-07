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

#ifndef NDNCERT_REDIRECTION_EMAIL_HPP
#define NDNCERT_REDIRECTION_EMAIL_HPP

#include "redirection-policy.hpp"

namespace ndncert {

/**
 * assign names base on client probe parameter
 */
class RedirectionEmail : public RedirectionPolicy
{
public:
  explicit RedirectionEmail(const std::string& format = "");

  bool
  isRedirecting(const std::multimap<std::string, std::string>& params) override;

private:
  std::string m_domain;
};

} // namespace ndncert

#endif // NDNCERT_REDIRECTION_EMAIL_HPP

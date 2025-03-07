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

#ifndef NDN_TESTS_IDENTITY_MANAGEMENT_FIXTURE_HPP
#define NDN_TESTS_IDENTITY_MANAGEMENT_FIXTURE_HPP

#include "detail/ndncert-common.hpp"

#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndncert {
namespace tests {

class IdentityManagementBaseFixture
{
public:
  ~IdentityManagementBaseFixture();

  bool
  saveCertToFile(const Data& obj, const std::string& filename);

protected:
  std::set<Name> m_identities;
  std::set<std::string> m_certFiles;
};

/**
 * @brief A test suite level fixture to help with identity management
 *
 * Test cases in the suite can use this fixture to create identities.  Identities,
 * certificates, and saved certificates are automatically removed during test teardown.
 */
class IdentityManagementFixture : public IdentityManagementBaseFixture
{
protected:
  using Identity = ndn::security::Identity;
  using Key      = ndn::security::Key;

public:
  IdentityManagementFixture();

  /**
   * @brief Add identity @p identityName
   * @return name of the created self-signed certificate
   */
  Identity
  addIdentity(const Name& identityName,
              const ndn::KeyParams& params = ndn::KeyChain::getDefaultKeyParams());

  /**
   *  @brief Save identity certificate to a file
   *  @param identity identity
   *  @param filename file name, should be writable
   *  @return whether successful
   */
  bool
  saveCertificate(const Identity& identity, const std::string& filename);

  /**
   * @brief Issue a certificate for \p subIdentityName signed by \p issuer
   *
   *  If identity does not exist, it is created.
   *  A new key is generated as the default key for identity.
   *  A default certificate for the key is signed by the issuer using its default certificate.
   *
   *  @return the sub identity
   */
  Identity
  addSubCertificate(const Name& subIdentityName, const Identity& issuer,
                    const ndn::KeyParams& params = ndn::KeyChain::getDefaultKeyParams());

  /**
   * @brief Add a self-signed certificate to @p key with issuer ID @p issuer
   */
  Certificate
  addCertificate(const Key& key, const std::string& issuer);

protected:
  ndn::KeyChain m_keyChain;
};

} // namespace tests
} // namespace ndncert

#endif // NDN_TESTS_IDENTITY_MANAGEMENT_FIXTURE_HPP

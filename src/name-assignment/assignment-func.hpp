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

#ifndef NDNCERT_ASSIGNMENT_FUNC_HPP
#define NDNCERT_ASSIGNMENT_FUNC_HPP

#include "detail/ca-request-state.hpp"

#include <map>

namespace ndncert {

class NameAssignmentFunc : boost::noncopyable
{
protected:
  explicit NameAssignmentFunc(const std::string& format = "");

public:
  virtual ~NameAssignmentFunc() = default;

  /**
   * @brief The name assignment function provided by the CA operator to generate available
   * namecomponents.
   *
   * The function does not guarantee that all the returned names are available. Therefore the
   * CA should further check the availability of each returned name and remove unavailable results.
   *
   * @param vector A list of parameter key-value pair used for name assignment.
   * @return a vector containing the possible namespaces derived from the parameters.
   */
  virtual std::vector<ndn::PartialName>
  assignName(const std::multimap<std::string, std::string>& params) = 0;

public:
  template <class AssignmentType>
  static void
  registerNameAssignmentFunc(const std::string& typeName)
  {
    CurriedFuncFactory& factory = getFactory();
    BOOST_ASSERT(factory.count(typeName) == 0);
    factory[typeName] = [](const std::string& format) { return std::make_unique<AssignmentType>(format); };
  }

  static std::unique_ptr<NameAssignmentFunc>
  createNameAssignmentFunc(const std::string& challengeType, const std::string& format = "");

NDNCERT_PUBLIC_WITH_TESTS_ELSE_PROTECTED:
  std::vector<std::string> m_nameFormat;

private:
  typedef std::function<std::unique_ptr<NameAssignmentFunc>(const std::string&)> FactoryCreateFunc;
  typedef std::map<std::string, FactoryCreateFunc> CurriedFuncFactory;

  static CurriedFuncFactory&
  getFactory();
};

#define NDNCERT_REGISTER_FUNCFACTORY(C, T)                                        \
  static class NdnCert##C##FuncFactoryRegistrationClass                           \
  {                                                                               \
  public:                                                                         \
    NdnCert##C##FuncFactoryRegistrationClass()                                    \
    {                                                                             \
      ::ndncert::NameAssignmentFunc::registerNameAssignmentFunc<C>(T);            \
    }                                                                             \
  } g_NdnCert##C##ChallengeRegistrationVariable

} // namespace ndncert

#endif // NDNCERT_ASSIGNMENT_FUNC_HPP

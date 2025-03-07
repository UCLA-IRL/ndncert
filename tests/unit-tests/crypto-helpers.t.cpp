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

#include "detail/crypto-helpers.hpp"
#include "test-common.hpp"

namespace ndncert {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestCryptoHelpers)

BOOST_AUTO_TEST_CASE(EcdhWithRawKey)
{
  ECDHState aliceState;
  auto alicePub = aliceState.getSelfPubKey();
  BOOST_CHECK(!alicePub.empty());

  ECDHState bobState;
  auto bobPub = bobState.getSelfPubKey();
  BOOST_CHECK(!bobPub.empty());

  auto aliceResult = aliceState.deriveSecret(bobPub);
  BOOST_CHECK(!aliceResult.empty());
  auto bobResult = bobState.deriveSecret(alicePub);
  BOOST_CHECK(!bobResult.empty());
  BOOST_CHECK_EQUAL_COLLECTIONS(aliceResult.begin(), aliceResult.end(), bobResult.begin(), bobResult.end());
}

BOOST_AUTO_TEST_CASE(EcdhWithRawKeyWrongInput)
{
  ECDHState aliceState;
  auto alicePub = aliceState.getSelfPubKey();
  BOOST_CHECK(!alicePub.empty());
  std::vector<uint8_t> fakePub(10, 0x0b);
  BOOST_CHECK_THROW(aliceState.deriveSecret(fakePub), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(HmacSha256)
{
  const uint8_t input[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                           0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                           0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
  const uint8_t key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                          0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
  const uint8_t expected[] = {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
                              0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
                              0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
                              0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};
  uint8_t result[32];
  hmacSha256(input, sizeof(input), key, sizeof(key), result);
  BOOST_CHECK_EQUAL_COLLECTIONS(result, result + sizeof(result), expected,
                                expected + sizeof(expected));
}

BOOST_AUTO_TEST_CASE(Hkdf1)
{
  // RFC5869 appendix A.1
  const uint8_t ikm[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                         0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                         0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
  const uint8_t salt[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                          0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
  const uint8_t info[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
                          0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
  const uint8_t expected[] = {
      0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
      0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
      0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34,
      0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};
  uint8_t result[42];
  auto resultLen = hkdf(ikm, sizeof(ikm), salt, sizeof(salt), result,
                        sizeof(result), info, sizeof(info));

  BOOST_CHECK_EQUAL(resultLen, sizeof(result));
  BOOST_CHECK_EQUAL_COLLECTIONS(result, result + sizeof(result), expected,
                                expected + sizeof(expected));
}

BOOST_AUTO_TEST_CASE(Hkdf2)
{
  // RFC5869 appendix A.2
  const uint8_t ikm[] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
      0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
      0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
      0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
      0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
  const uint8_t salt[] = {
      0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
      0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
      0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,
      0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
      0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
      0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
      0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};
  const uint8_t info[] = {
      0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
      0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
      0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3,
      0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
      0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb,
      0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
      0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
  const uint8_t expected[] = {
      0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c,
      0x59, 0x6a, 0x49, 0x34, 0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8,
      0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c, 0x59, 0x04, 0x5a, 0x99,
      0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
      0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8, 0x36, 0x77, 0x93, 0xa9,
      0xac, 0xa3, 0xdb, 0x71, 0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87,
      0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f, 0x1d, 0x87};

  uint8_t result[82];
  auto resultLen = hkdf(ikm, sizeof(ikm), salt, sizeof(salt), result,
                        sizeof(result), info, sizeof(info));

  BOOST_CHECK_EQUAL(resultLen, sizeof(result));
  BOOST_CHECK_EQUAL_COLLECTIONS(result, result + sizeof(result), expected,
                                expected + sizeof(expected));
}

BOOST_AUTO_TEST_CASE(Hkdf3)
{
  // RFC5869 appendix A.3
  const uint8_t ikm[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                         0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                         0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
  const uint8_t expected[] = {
      0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80,
      0x2a, 0x06, 0x3c, 0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1,
      0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d, 0x9d,
      0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8};
  uint8_t result[42];

  auto resultLen = hkdf(ikm, sizeof(ikm), nullptr, 0, result,
                        sizeof(result), nullptr, 0);

  BOOST_CHECK_EQUAL(resultLen, sizeof(result));
  BOOST_CHECK_EQUAL_COLLECTIONS(result, result + sizeof(result), expected,
                                expected + sizeof(expected));
}

BOOST_AUTO_TEST_CASE(AesGcm1)
{
  // Test case from NIST Cryptographic Algorithm Validation Program
  // https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES
  // Count = 0
  // Key = cf063a34d4a9a76c2c86787d3f96db71
  // IV = 113b9785971864c83b01c787
  // CT =
  // AAD =
  // Tag = 72ac8493e3a5228b5d130a69d2510e42
  // PT =
  const uint8_t key[] = {0xcf, 0x06, 0x3a, 0x34, 0xd4, 0xa9, 0xa7, 0x6c,
                         0x2c, 0x86, 0x78, 0x7d, 0x3f, 0x96, 0xdb, 0x71};
  const uint8_t iv[] = {0x11, 0x3b, 0x97, 0x85, 0x97, 0x18,
                        0x64, 0xc8, 0x3b, 0x01, 0xc7, 0x87};
  const uint8_t expected_tag[] = {0x72, 0xac, 0x84, 0x93, 0xe3, 0xa5,
                                  0x22, 0x8b, 0x5d, 0x13, 0x0a, 0x69,
                                  0xd2, 0x51, 0x0e, 0x42};

  uint8_t ciphertext[256] = {0};
  uint8_t tag[16] = {0};
  const uint8_t empty_buffer[1] = {0};
  int size = aesGcm128Encrypt(empty_buffer, 0, empty_buffer, 0, key, iv, ciphertext, tag);
  BOOST_CHECK(size == 0);
  BOOST_CHECK_EQUAL_COLLECTIONS(tag, tag + 16, expected_tag, expected_tag + sizeof(expected_tag));

  uint8_t decrypted[256] = {0};
  size = aesGcm128Decrypt(ciphertext, size, empty_buffer, 0, tag, key, iv, decrypted);
  BOOST_CHECK(size == 0);
}

BOOST_AUTO_TEST_CASE(AesGcm2)
{
  // Test case from NIST Cryptographic Algorithm Validation Program
  // https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES
  // Count = 1
  // Key = 2370e320d4344208e0ff5683f243b213
  // IV = 04dbb82f044d30831c441228
  // CT =
  // AAD = d43a8e5089eea0d026c03a85178b27da
  // Tag = 2a049c049d25aa95969b451d93c31c6e
  // PT =
  const uint8_t key[] = {0x23, 0x70, 0xe3, 0x20, 0xd4, 0x34, 0x42, 0x08,
                         0xe0, 0xff, 0x56, 0x83, 0xf2, 0x43, 0xb2, 0x13};
  const uint8_t iv[] = {0x04, 0xdb, 0xb8, 0x2f, 0x04, 0x4d,
                        0x30, 0x83, 0x1c, 0x44, 0x12, 0x28};
  const uint8_t aad[] = {0xd4, 0x3a, 0x8e, 0x50, 0x89, 0xee, 0xa0, 0xd0,
                         0x26, 0xc0, 0x3a, 0x85, 0x17, 0x8b, 0x27, 0xda};
  const uint8_t expected_tag[] = {0x2a, 0x04, 0x9c, 0x04, 0x9d, 0x25,
                                  0xaa, 0x95, 0x96, 0x9b, 0x45, 0x1d,
                                  0x93, 0xc3, 0x1c, 0x6e};

  uint8_t ciphertext[256] = {0};
  uint8_t tag[16] = {0};
  const uint8_t empty_buffer[1] = {0};
  int size = aesGcm128Encrypt(empty_buffer, 0, aad, sizeof(aad), key, iv, ciphertext, tag);
  BOOST_CHECK(size == 0);
  BOOST_CHECK_EQUAL_COLLECTIONS(tag, tag + 16, expected_tag, expected_tag + sizeof(expected_tag));

  uint8_t decrypted[256] = {0};
  size = aesGcm128Decrypt(ciphertext, size, aad, sizeof(aad), tag, key, iv, decrypted);
  BOOST_CHECK(size == 0);
}

BOOST_AUTO_TEST_CASE(AesGcm3)
{
  // Test case from NIST Cryptographic Algorithm Validation Program
  // https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES
  // Count = 0
  // Key = bc22f3f05cc40db9311e4192966fee92
  // IV = 134988e662343c06d3ab83db
  // CT = 4c0168ab95d3a10ef25e5924108389365c67d97778995892d9fd46897384af61fc559212b3267e90fe4df7bfd1fbed46f4b9ee
  // AAD = 10087e6ed81049b509c31d12fee88c64
  // Tag = 771357958a316f166bd0dacc98ea801a
  // PT = 337c1bc992386cf0f957617fe4d5ec1218ae1cc40369305518eb177e9b15c1646b142ff71237efaa58790080cd82e8848b295c
  const uint8_t key[] = {0xbc, 0x22, 0xf3, 0xf0, 0x5c, 0xc4, 0x0d, 0xb9,
                         0x31, 0x1e, 0x41, 0x92, 0x96, 0x6f, 0xee, 0x92};
  const uint8_t iv[] = {0x13, 0x49, 0x88, 0xe6, 0x62, 0x34,
                        0x3c, 0x06, 0xd3, 0xab, 0x83, 0xdb};
  const uint8_t aad[] = {0x10, 0x08, 0x7e, 0x6e, 0xd8, 0x10, 0x49, 0xb5,
                         0x09, 0xc3, 0x1d, 0x12, 0xfe, 0xe8, 0x8c, 0x64};
  const uint8_t expected_ciphertext[] = {
      0x4c, 0x01, 0x68, 0xab, 0x95, 0xd3, 0xa1, 0x0e, 0xf2, 0x5e, 0x59,
      0x24, 0x10, 0x83, 0x89, 0x36, 0x5c, 0x67, 0xd9, 0x77, 0x78, 0x99,
      0x58, 0x92, 0xd9, 0xfd, 0x46, 0x89, 0x73, 0x84, 0xaf, 0x61, 0xfc,
      0x55, 0x92, 0x12, 0xb3, 0x26, 0x7e, 0x90, 0xfe, 0x4d, 0xf7, 0xbf,
      0xd1, 0xfb, 0xed, 0x46, 0xf4, 0xb9, 0xee};
  const uint8_t expected_tag[] = {0x77, 0x13, 0x57, 0x95, 0x8a, 0x31,
                                  0x6f, 0x16, 0x6b, 0xd0, 0xda, 0xcc,
                                  0x98, 0xea, 0x80, 0x1a};
  const uint8_t plaintext[] = {
      0x33, 0x7c, 0x1b, 0xc9, 0x92, 0x38, 0x6c, 0xf0, 0xf9, 0x57, 0x61,
      0x7f, 0xe4, 0xd5, 0xec, 0x12, 0x18, 0xae, 0x1c, 0xc4, 0x03, 0x69,
      0x30, 0x55, 0x18, 0xeb, 0x17, 0x7e, 0x9b, 0x15, 0xc1, 0x64, 0x6b,
      0x14, 0x2f, 0xf7, 0x12, 0x37, 0xef, 0xaa, 0x58, 0x79, 0x00, 0x80,
      0xcd, 0x82, 0xe8, 0x84, 0x8b, 0x29, 0x5c};

  uint8_t ciphertext[256] = {0};
  uint8_t tag[16] = {0};
  int size = aesGcm128Encrypt(plaintext, sizeof(plaintext), aad, sizeof(aad), key, iv, ciphertext, tag);
  BOOST_CHECK_EQUAL_COLLECTIONS(ciphertext, ciphertext + size,
                                expected_ciphertext, expected_ciphertext + sizeof(expected_ciphertext));
  BOOST_CHECK_EQUAL_COLLECTIONS(tag, tag + 16, expected_tag, expected_tag + sizeof(expected_tag));

  uint8_t decrypted[256] = {0};
  size = aesGcm128Decrypt(ciphertext, size, aad, sizeof(aad), tag, key, iv, decrypted);
  BOOST_CHECK_EQUAL_COLLECTIONS(decrypted, decrypted + size,
                                plaintext, plaintext + sizeof(plaintext));
}

BOOST_AUTO_TEST_CASE(AesIV)
{
  const uint8_t key[] = {0xbc, 0x22, 0xf3, 0xf0, 0x5c, 0xc4, 0x0d, 0xb9,
                         0x31, 0x1e, 0x41, 0x92, 0x96, 0x6f, 0xee, 0x92};
  const std::string plaintext = "alongstringalongstringalongstringalongstringalongstringalongstringalongstringalongstring";
  const std::string associatedData = "test";
  std::vector<uint8_t> encryptionIv = {};
  auto block = encodeBlockWithAesGcm128(ndn::tlv::Content, key, (uint8_t*)plaintext.c_str(), plaintext.size(),
                                        (uint8_t*)associatedData.c_str(), associatedData.size(), encryptionIv);
  block.parse();
  auto ivBlock = block.get(tlv::InitializationVector);
  ndn::Buffer ivBuf(ivBlock.value(), ivBlock.value_size());
  BOOST_CHECK_EQUAL(ivBuf.size(), 12);
  BOOST_CHECK_EQUAL(loadBigU32(&encryptionIv[8]), 6);
  BOOST_CHECK_EQUAL(loadBigU32(&ivBuf[8]), 0);

  block = encodeBlockWithAesGcm128(ndn::tlv::ApplicationParameters, key, (uint8_t*)plaintext.c_str(), plaintext.size(),
                                   (uint8_t*)associatedData.c_str(), associatedData.size(), encryptionIv);
  block.parse();
  ivBlock = block.get(tlv::InitializationVector);
  ndn::Buffer ivBuf2(ivBlock.value(), ivBlock.value_size());
  BOOST_CHECK_EQUAL(std::memcmp(ivBuf2.data(), encryptionIv.data(), 8), 0);
}

BOOST_AUTO_TEST_CASE(BlockEncodingDecoding)
{
  const uint8_t key[] = {0xbc, 0x22, 0xf3, 0xf0, 0x5c, 0xc4, 0x0d, 0xb9,
                         0x31, 0x1e, 0x41, 0x92, 0x96, 0x6f, 0xee, 0x92};
  const std::string plaintext = "alongstringalongstringalongstringalongstringalongstringalongstringalongstringalongstring";
  const std::string plaintext2 = "shortstring";
  const std::string associatedData = "right";
  const std::string wrongAssociatedData = "wrong";
  std::vector<uint8_t> encryptionIv;
  std::vector<uint8_t> decryptionIv;
  // long string encryption
  auto block = encodeBlockWithAesGcm128(ndn::tlv::Content, key, (uint8_t*)plaintext.c_str(), plaintext.size(),
                                        (uint8_t*)associatedData.c_str(), associatedData.size(), encryptionIv);
  BOOST_CHECK_EQUAL(encryptionIv.size(), 12);
  // the decryption's random component cannot be the same as encryption IV
  BOOST_CHECK_THROW(decodeBlockWithAesGcm128(block, key,
                                            (uint8_t*)associatedData.c_str(),
                                            associatedData.size(), decryptionIv, encryptionIv),
                    std::runtime_error);
  auto decoded = decodeBlockWithAesGcm128(block, key, (uint8_t*)associatedData.c_str(), associatedData.size(),
                                          decryptionIv, std::vector<uint8_t>());
  BOOST_CHECK_EQUAL(decryptionIv.size(), 12);
  BOOST_CHECK_EQUAL(plaintext, std::string(decoded.get<char>(), decoded.size()));

  // short string encryption
  block = encodeBlockWithAesGcm128(ndn::tlv::Content, key, (uint8_t*)plaintext2.c_str(), plaintext2.size(),
                                   (uint8_t*)associatedData.c_str(), associatedData.size(), encryptionIv);
  decoded = decodeBlockWithAesGcm128(block, key, (uint8_t*)associatedData.c_str(), associatedData.size(),
                                     decryptionIv, std::vector<uint8_t>());
  BOOST_CHECK_EQUAL(plaintext2, std::string(decoded.get<char>(), decoded.size()));

  // use wrong associated data
  BOOST_CHECK_THROW(decodeBlockWithAesGcm128(block, key,
                                             (uint8_t*)wrongAssociatedData.c_str(),
                                             wrongAssociatedData.size(), decryptionIv, std::vector<uint8_t>()),
                    std::runtime_error);
  // use wrong last observed IV
  decryptionIv[0] += 1;
  BOOST_CHECK_THROW(decodeBlockWithAesGcm128(block, key,
                                             (uint8_t*)associatedData.c_str(),
                                             associatedData.size(), decryptionIv, std::vector<uint8_t>()),
                    std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END() // TestCryptoHelpers

} // namespace tests
} // namespace ndncert

/**
 * BSD 3-Clause License
 *
 * Copyright (c) 2026, RavenHammer Research Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "certificate_manager.hpp"
#include "Console.hpp"
#include <fstream>
#include <iomanip>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sstream>

namespace acme {

  CertificateManager::CertificateManager(const std::string &ca_key_path,
                                         const std::string &ca_cert_path,
                                         const std::string &server_key_path,
                                         const std::string &server_cert_path)
      : ca_key_path_(ca_key_path), ca_cert_path_(ca_cert_path),
        server_key_path_(server_key_path), server_cert_path_(server_cert_path) {
  }

  bool CertificateManager::initializeCA() {
    // Check if CA already exists
    std::ifstream ca_cert_file(ca_cert_path_);
    if (ca_cert_file.good()) {
      console::e("CA already exists, skipping initialization");
      return true;
    }

    console::e("Initializing CA...");

    // Create self-signed CA certificate
    if (!createSelfSignedCA()) {
      console::e("Failed to create self-signed CA");
      return false;
    }

    // Create server certificate
    if (!createServerCertificate()) {
      console::e("Failed to create server certificate");
      return false;
    }

    console::e("CA initialized successfully");
    return true;
  }

  bool CertificateManager::createSelfSignedCA() {
    // Generate CA key
    EVP_PKEY *ca_key = generateRSAKey(4096);
    if (!ca_key) {
      console::e("Failed to generate CA key");
      return false;
    }

    // Generate CA certificate
    X509 *ca_cert = generateX509("ACME CA", ca_key, true);
    if (!ca_cert) {
      EVP_PKEY_free(ca_key);
      console::e("Failed to generate CA certificate");
      return false;
    }

    // Save CA key
    if (!saveKey(ca_key_path_, ca_key)) {
      X509_free(ca_cert);
      EVP_PKEY_free(ca_key);
      console::e("Failed to save CA key");
      return false;
    }

    // Save CA certificate
    if (!saveCert(ca_cert_path_, ca_cert)) {
      X509_free(ca_cert);
      EVP_PKEY_free(ca_key);
      console::e("Failed to save CA certificate");
      return false;
    }

    X509_free(ca_cert);
    EVP_PKEY_free(ca_key);

    return true;
  }

  bool CertificateManager::createServerCertificate() {
    // Generate server key
    EVP_PKEY *server_key = generateRSAKey(2048);
    if (!server_key) {
      console::e("Failed to generate server key");
      return false;
    }

    // Generate server certificate
    X509 *server_cert =
        generateX509("acme-server.example.com", server_key, false);
    if (!server_cert) {
      EVP_PKEY_free(server_key);
      console::e("Failed to generate server certificate");
      return false;
    }

    // Save server key
    if (!saveKey(server_key_path_, server_key)) {
      X509_free(server_cert);
      EVP_PKEY_free(server_key);
      console::e("Failed to save server key");
      return false;
    }

    // Save server certificate
    if (!saveCert(server_cert_path_, server_cert)) {
      X509_free(server_cert);
      EVP_PKEY_free(server_key);
      console::e("Failed to save server certificate");
      return false;
    }

    X509_free(server_cert);
    EVP_PKEY_free(server_key);

    return true;
  }

  bool CertificateManager::generateCertificate(const std::string &common_name,
                                               const std::string &csr_pem) {
    // Parse CSR
    BIO *bio = BIO_new_mem_buf(csr_pem.c_str(), csr_pem.length());
    if (!bio) {
      console::e("Failed to create BIO for CSR");
      return false;
    }

    X509_REQ *csr = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!csr) {
      console::e("Failed to parse CSR");
      return false;
    }

    // Extract public key from CSR
    EVP_PKEY *csr_key = X509_REQ_get_pubkey(csr);
    if (!csr_key) {
      X509_REQ_free(csr);
      console::e("Failed to extract public key from CSR");
      return false;
    }

    // Generate certificate
    X509 *new_cert = generateX509(common_name, csr_key, false);
    if (!new_cert) {
      EVP_PKEY_free(csr_key);
      X509_REQ_free(csr);
      console::e("Failed to generate certificate");
      return false;
    }

    // Sign with CA
    BIO *ca_cert_bio = BIO_new_file(ca_cert_path_.c_str(), "r");
    if (!ca_cert_bio) {
      X509_free(new_cert);
      EVP_PKEY_free(csr_key);
      X509_REQ_free(csr);
      console::e("Failed to open CA certificate");
      return false;
    }

    X509 *ca_cert = PEM_read_bio_X509(ca_cert_bio, nullptr, nullptr, nullptr);
    BIO_free(ca_cert_bio);

    if (!ca_cert) {
      X509_free(new_cert);
      EVP_PKEY_free(csr_key);
      X509_REQ_free(csr);
      console::e("Failed to read CA certificate");
      return false;
    }

    BIO *ca_key_bio = BIO_new_file(ca_key_path_.c_str(), "r");
    if (!ca_key_bio) {
      X509_free(ca_cert);
      X509_free(new_cert);
      EVP_PKEY_free(csr_key);
      X509_REQ_free(csr);
      console::e("Failed to open CA key");
      return false;
    }

    EVP_PKEY *ca_key =
        PEM_read_bio_PrivateKey(ca_key_bio, nullptr, nullptr, nullptr);
    BIO_free(ca_key_bio);

    if (!ca_key) {
      X509_free(ca_cert);
      X509_free(new_cert);
      EVP_PKEY_free(csr_key);
      X509_REQ_free(csr);
      console::e("Failed to read CA key");
      return false;
    }

    // Sign certificate
    if (!X509_sign(new_cert, ca_key, EVP_sha256())) {
      console::e("Failed to sign certificate");
      X509_free(ca_cert);
      X509_free(new_cert);
      EVP_PKEY_free(ca_key);
      EVP_PKEY_free(csr_key);
      X509_REQ_free(csr);
      return false;
    }

    // Save certificate
    std::string cert_path = "/etc/ssl/" + common_name + ".crt";
    if (!saveCert(cert_path, new_cert)) {
      X509_free(ca_cert);
      X509_free(new_cert);
      EVP_PKEY_free(ca_key);
      EVP_PKEY_free(csr_key);
      X509_REQ_free(csr);
      console::e("Failed to save certificate");
      return false;
    }

    X509_free(ca_cert);
    X509_free(new_cert);
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(csr_key);
    X509_REQ_free(csr);

    return true;
  }

  EVP_PKEY *CertificateManager::generateRSAKey(size_t key_size) {
    EVP_PKEY *key = EVP_PKEY_new();
    if (!key) {
      return nullptr;
    }

    RSA *rsa = RSA_new();
    if (!rsa) {
      EVP_PKEY_free(key);
      return nullptr;
    }

    BIGNUM *bn = BN_new();
    if (!bn) {
      RSA_free(rsa);
      EVP_PKEY_free(key);
      return nullptr;
    }

    BN_set_word(bn, RSA_F4);

    if (RSA_generate_key_ex(rsa, key_size, bn, nullptr) != 1) {
      BN_free(bn);
      RSA_free(rsa);
      EVP_PKEY_free(key);
      return nullptr;
    }

    BN_free(bn);

    if (EVP_PKEY_assign_RSA(key, rsa) != 1) {
      RSA_free(rsa);
      EVP_PKEY_free(key);
      return nullptr;
    }

    return key;
  }

  X509 *CertificateManager::generateX509(const std::string &common_name,
                                         EVP_PKEY *key, bool is_ca) {
    X509 *cert = X509_new();
    if (!cert) {
      return nullptr;
    }

    // Set version
    X509_set_version(cert, 2);

    // Set serial number
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    if (!serial) {
      X509_free(cert);
      return nullptr;
    }

    if (RAND_bytes((unsigned char *)serial->data, serial->length) != 1) {
      ASN1_INTEGER_free(serial);
      X509_free(cert);
      return nullptr;
    }

    X509_set_serialNumber(cert, serial);
    ASN1_INTEGER_free(serial);

    // Set validity
    ASN1_TIME *not_before = ASN1_TIME_new();
    ASN1_TIME *not_after = ASN1_TIME_new();
    if (!not_before || !not_after) {
      X509_free(cert);
      return nullptr;
    }

    ASN1_TIME_set(not_before, time(nullptr));
    ASN1_TIME_set(not_after, time(nullptr) + 365 * 24 * 60 * 60);

    X509_set_notBefore(cert, not_before);
    X509_set_notAfter(cert, not_after);

    ASN1_TIME_free(not_before);
    ASN1_TIME_free(not_after);

    // Set subject
    X509_NAME *name = X509_NAME_new();
    if (!name) {
      X509_free(cert);
      return nullptr;
    }

    X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char *>(common_name.c_str()),
        common_name.length(), -1, 0);

    X509_set_subject_name(cert, name);
    X509_NAME_free(name);

    // Set issuer
    X509_set_issuer_name(cert, name);

    // Set public key
    if (X509_set_pubkey(cert, key) != 1) {
      X509_free(cert);
      return nullptr;
    }

    // Add extensions
    addExtensions(cert, common_name, is_ca);

    return cert;
  }

  void CertificateManager::addExtensions(X509 *cert,
                                         const std::string &common_name,
                                         bool is_ca) {
    // Basic constraints
    X509_EXTENSION *ext =
        X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints,
                            is_ca ? "CA:TRUE" : "CA:FALSE");
    if (ext) {
      X509_add_ext(cert, ext, 0);
      X509_EXTENSION_free(ext);
    }

    // Key usage
    ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_key_usage,
                              "digitalSignature,keyCertSign,cRLSign");
    if (ext) {
      X509_add_ext(cert, ext, 1);
      X509_EXTENSION_free(ext);
    }

    // Subject key identifier
    ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_key_identifier,
                              "hash");
    if (ext) {
      X509_add_ext(cert, ext, 2);
      X509_EXTENSION_free(ext);
    }

    // Authority key identifier
    ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_authority_key_identifier,
                              "keyid,issuer");
    if (ext) {
      X509_add_ext(cert, ext, 3);
      X509_EXTENSION_free(ext);
    }

    // Subject alternative name
    std::string san = "DNS:" + common_name;
    ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name,
                              san.c_str());
    if (ext) {
      X509_add_ext(cert, ext, 4);
      X509_EXTENSION_free(ext);
    }
  }

  bool CertificateManager::saveKey(const std::string &key_path, EVP_PKEY *key) {
    BIO *bio = BIO_new_file(key_path.c_str(), "w");
    if (!bio) {
      return false;
    }

    if (!PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr,
                                  nullptr)) {
      BIO_free(bio);
      return false;
    }

    BIO_free(bio);
    return true;
  }

  bool CertificateManager::saveCert(const std::string &cert_path, X509 *cert) {
    BIO *bio = BIO_new_file(cert_path.c_str(), "w");
    if (!bio) {
      return false;
    }

    if (!PEM_write_bio_X509(bio, cert)) {
      BIO_free(bio);
      return false;
    }

    BIO_free(bio);
    return true;
  }

} // namespace acme
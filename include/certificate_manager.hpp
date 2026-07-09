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

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace acme {

  class CertificateManager {
  public:
    CertificateManager(const std::string &ca_key_path,
                       const std::string &ca_cert_path,
                       const std::string &server_key_path,
                       const std::string &server_cert_path);

    bool initializeCA();
    bool generateCertificate(const std::string &common_name,
                             const std::string &csr_pem);
    std::string getCAKeyPath() const { return ca_key_path_; }
    std::string getCACertPath() const { return ca_cert_path_; }

  private:
    std::string ca_key_path_;
    std::string ca_cert_path_;
    std::string server_key_path_;
    std::string server_cert_path_;

    bool createSelfSignedCA();
    bool createServerCertificate();
    bool saveKey(const std::string &key_path, EVP_PKEY *key);
    bool saveCert(const std::string &cert_path, X509 *cert);
    EVP_PKEY *generateRSAKey(size_t key_size = 2048);
    X509 *generateX509(const std::string &common_name, EVP_PKEY *key,
                       bool is_ca = false);
    void addExtensions(X509 *cert, const std::string &common_name, bool is_ca);
  };

} // namespace acme
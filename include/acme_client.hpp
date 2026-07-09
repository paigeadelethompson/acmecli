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

#include <gssapi/gssapi.h>

#include "HTTPClient.hpp"
#include "json/json.h"

// OpenSSL types
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace acme {

  class KerberosAuth;

  class ACMEClient {
  public:
    ACMEClient(
        const std::string &config_path = "/etc/acmecli/acme_client.conf");
    ~ACMEClient();

    bool initialize();
    void shutdown();

    // ACME protocol operations
    Json::Value getDirectory();
    Json::Value newNonce();
    Json::Value newAccount(const Json::Value &request);
    Json::Value getAccount(const std::string &account_id);
    Json::Value newOrder(const Json::Value &request);
    Json::Value getOrder(const std::string &order_id);
    Json::Value finalizeOrder(const std::string &order_id,
                              const Json::Value &request);
    Json::Value getCertificate(const std::string &cert_id);
    Json::Value revokeCertificate(const Json::Value &request);

  private:
    std::string server_url_;
    std::string account_id_;
    std::string config_path_;

    std::unique_ptr<KerberosAuth> kerberos_auth_;
    std::unique_ptr<HTTPClient> http_client_;

    std::string current_nonce_;
    std::string current_jws_;

    Json::Value sendRequest(const std::string &path, const std::string &method,
                            const Json::Value &payload);
    std::string generateJWS(const Json::Value &payload);
    bool verifyJWS(const Json::Value &jws);
    std::string extractCNFromCSR(const std::string &csr_pem);
    bool validateCSR(const Json::Value &csr);
    bool createCSR(const std::string &common_name, std::string &csr_pem);

    // Certificate generation
    EVP_PKEY *generateRSAKey(size_t key_size);
    X509 *generateX509(const std::string &common_name, EVP_PKEY *key,
                       bool is_ca);
    void addExtensions(X509 *cert, const std::string &common_name, bool is_ca);

    // GSSAPI helpers
    OM_uint32 acquireCredentials(const std::string &principal,
                                 gss_cred_id_t *cred);
    OM_uint32 initSecurityContext(const std::string &target_principal,
                                  gss_ctx_id_t *context,
                                  gss_cred_id_t client_cred);
    OM_uint32 wrapToken(gss_ctx_id_t context, const std::string &token,
                        std::string &wrapped_token);
    OM_uint32 unwrapToken(gss_ctx_id_t context,
                          const std::string &wrapped_token, std::string &token);
    void cleanupGSS(gss_ctx_id_t context, gss_cred_id_t cred);
  };

} // namespace acme
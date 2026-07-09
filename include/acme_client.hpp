#pragma once

#include <string>
#include <memory>
#include <vector>
#include <optional>

#include <gssapi/gssapi.h>

#include "json/json.h"
#include "HTTPClient.hpp"

// OpenSSL types
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace acme {

class KerberosAuth;

class ACMEClient {
public:
    ACMEClient(const std::string& config_path = "/etc/acmecli/acme_client.conf");
    ~ACMEClient();

    bool initialize();
    void shutdown();

    // ACME protocol operations
    Json::Value getDirectory();
    Json::Value newNonce();
    Json::Value newAccount(const Json::Value& request);
    Json::Value getAccount(const std::string& account_id);
    Json::Value newOrder(const Json::Value& request);
    Json::Value getOrder(const std::string& order_id);
    Json::Value finalizeOrder(const std::string& order_id, const Json::Value& request);
    Json::Value getCertificate(const std::string& cert_id);
    Json::Value revokeCertificate(const Json::Value& request);

private:
    std::string server_url_;
    std::string account_id_;
    std::string config_path_;

    std::unique_ptr<KerberosAuth> kerberos_auth_;    std::unique_ptr\u003cHTTPClient\u003e http_client_;
    std::string current_nonce_;
    std::string current_jws_;

    Json::Value sendRequest(const std::string& path, const std::string& method, const Json::Value& payload);
    std::string generateJWS(const Json::Value& payload);
    bool verifyJWS(const Json::Value& jws);
    std::string extractCNFromCSR(const std::string& csr_pem);
    bool validateCSR(const Json::Value& csr);
    bool createCSR(const std::string& common_name, std::string& csr_pem);

    // Certificate generation
    EVP_PKEY* generateRSAKey(size_t key_size);
    X509* generateX509(const std::string& common_name, EVP_PKEY* key, bool is_ca);
    void addExtensions(X509* cert, const std::string& common_name, bool is_ca);

    // GSSAPI helpers
    OM_uint32 acquireCredentials(const std::string& principal, gss_cred_id_t* cred);
    OM_uint32 initSecurityContext(const std::string& target_principal, gss_ctx_id_t* context, gss_cred_id_t client_cred);
    OM_uint32 wrapToken(gss_ctx_id_t context, const std::string& token, std::string& wrapped_token);
    OM_uint32 unwrapToken(gss_ctx_id_t context, const std::string& wrapped_token, std::string& token);
    void cleanupGSS(gss_ctx_id_t context, gss_cred_id_t cred);
};

} // namespace acme
#pragma once

#include <string>
#include <memory>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <chrono>
#include <optional>

#include <gssapi/gssapi.h>

#include "json/json.h"

namespace acme {

class CertificateManager;
class PolicyManager;
class KerberosAuth;

class ACMEServer {
public:
    ACMEServer(const std::string& config_path = "/etc/acmecli/acmed.conf");
    ~ACMEServer();

    bool initialize();
    void run();
    void stop();

    // ACME protocol endpoints
    Json::Value handleDirectory();
    Json::Value handleNewNonce();
    Json::Value handleNewAccount(const Json::Value& request);
    Json::Value handleAccount(const std::string& account_id, const Json::Value& request);
    Json::Value handleNewOrder(const Json::Value& request);
    Json::Value handleOrder(const std::string& order_id, const Json::Value& request);
    Json::Value handleFinalizeOrder(const std::string& order_id, const Json::Value& request);
    Json::Value handleCertificate(const std::string& cert_id, const Json::Value& request);
    Json::Value handleRevokeCertificate(const Json::Value& request);

private:
    std::string config_path_;
    std::string server_key_path_;
    std::string server_cert_path_;
    std::string ca_key_path_;
    std::string ca_cert_path_;
    std::string policy_file_path_;
    std::string kdc_principal_;
    std::string kdc_keytab_;

    std::unique_ptr<CertificateManager> cert_manager_;
    std::unique_ptr<PolicyManager> policy_manager_;
    std::unique_ptr<KerberosAuth> kerberos_auth_;

    std::unordered_map<std::string, std::string> accounts_;
    std::unordered_map<std::string, Json::Value> orders_;
    std::unordered_map<std::string, std::string> certificates_;

    std::mutex accounts_mutex_;
    std::mutex orders_mutex_;
    std::mutex certificates_mutex_;

    std::string generateNonce();
    std::string generateJWS(const Json::Value& payload, const std::string& account_key);
    bool verifyJWS(const Json::Value& jws, std::string& account_id);
    bool validatePolicy(const std::string& principal, const std::string& cn);
    bool validateCSR(const Json::Value& csr);
    bool generateCertificate(const std::string& account_id, const std::string& cn, const std::string& csr_pem);
    bool revokeCertificate(const std::string& cert_id);
    std::string extractCNFromCSR(const std::string& csr_pem);

    // GSSAPI helpers
    OM_uint32 acquireCredentials(const std::string& principal, gss_cred_id_t* cred);
    OM_uint32 acceptSecurityContext(gss_ctx_id_t* context, gss_cred_id_t server_cred);
    OM_uint32 verifyToken(gss_ctx_id_t context, const std::string& token, std::string& principal);
    void cleanupGSS(gss_ctx_id_t context, gss_cred_id_t cred);
};

} // namespace acme
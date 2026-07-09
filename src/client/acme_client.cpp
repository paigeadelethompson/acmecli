#include "acme_client.hpp"
#include "kerberos_auth.hpp"
#include "console.hpp"
#include "HTTPClient.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <random>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <openssl/bn.h>

namespace acme {

ACMEClient::ACMEClient(const std::string& config_path)
    : config_path_(config_path) {
}

ACMEClient::~ACMEClient() {
    shutdown();
}

bool ACMEClient::initialize() {
    // Load configuration
    std::ifstream config_file(config_path_);
    if (!config_file.is_open()) {
        console::e("Error: Could not open config file: {}", config_path_);
        return false;
    }

    Json::Value config;
    config_file >> config;

    // Extract configuration values
    std::string server_url = config.get("server_url", "http://localhost:8080").asString();
    std::string kdc_principal = config.get("kdc_principal", "acme/client@REALM").asString();
    std::string kdc_keytab = config.get("kdc_keytab", "/etc/acmecli/client.keytab").asString();

    // Initialize Kerberos
    kerberos_auth_ = std::make_unique<KerberosAuth>(kdc_principal, kdc_keytab);

    // Initialize HTTP client with Kerberos support
    http_client_ = std::make_unique<HTTPClient>(kdc_principal, kdc_keytab);
    if (!http_client_->initialize()) {
        console::e("Failed to initialize HTTP client");
        return false;
    }

    console::e("ACME Client initialized successfully");
    return true;
}

void ACMEClient::shutdown() {
    if (kerberos_auth_) {
        kerberos_auth_.reset();
    }
    if (http_client_) {
        http_client_.reset();
    }
}

Json::Value ACMEClient::getDirectory() {
    Json::Value response = sendRequest("/acme/dir", "GET", Json::Value());
    return response;
}

Json::Value ACMEClient::newNonce() {
    Json::Value response = sendRequest("/acme/new-nonce", "GET", Json::Value());
    return response;
}

Json::Value ACMEClient::newAccount(const Json::Value& request) {
    Json::Value response = sendRequest("/acme/new-account", "POST", request);
    return response;
}

Json::Value ACMEClient::getAccount(const std::string& account_id) {
    Json::Value response = sendRequest("/acme/account/" + account_id, "GET", Json::Value());
    return response;
}

Json::Value ACMEClient::newOrder(const Json::Value& request) {
    Json::Value response = sendRequest("/acme/new-order", "POST", request);
    return response;
}

Json::Value ACMEClient::getOrder(const std::string& order_id) {
    Json::Value response = sendRequest("/acme/order/" + order_id, "GET", Json::Value());
    return response;
}

Json::Value ACMEClient::finalizeOrder(const std::string& order_id, const Json::Value& request) {
    Json::Value response = sendRequest("/acme/order/" + order_id + "/finalize", "POST", request);
    return response;
}

Json::Value ACMEClient::getCertificate(const std::string& cert_id) {
    Json::Value response = sendRequest("/acme/cert/" + cert_id, "GET", Json::Value());
    return response;
}

Json::Value ACMEClient::revokeCertificate(const Json::Value& request) {
    Json::Value response = sendRequest("/acme/revoke-cert", "POST", request);
    return response;
}

Json::Value ACMEClient::sendRequest(const std::string& path, const std::string& method, const Json::Value& payload) {
    std::string url = server_url_ + path;
    std::string response_data;

    // Build JSON payload string
    std::string payload_str;
    if (!payload.isNull()) {
        Json::FastWriter writer;
        payload_str = writer.write(payload);
    }

    // Use HTTPClient for requests
    Response response;
    bool success = false;

    if (method == "GET") {
        success = http_client_->get(url, response);
    } else if (method == "POST") {
        success = http_client_->post(url, payload_str, response);
    } else if (method == "PUT") {
        success = http_client_->put(url, payload_str, response);
    } else if (method == "DELETE") {
        success = http_client_->del(url, response);
    }

    if (!success) {
        console::e("HTTP request failed: {}", http_client_->getLastError());
        return Json::Value();
    }

    // Parse response
    Json::Value json_response;
    Json::Reader reader;
    if (!reader.parse(response.getBody(), json_response)) {
        console::e("Failed to parse JSON response");
        return Json::Value();
    }

    return json_response;
}

std::string ACMEClient::generateJWS(const Json::Value& payload) {
    // TODO: Implement JWS generation with account key
    // For now, return placeholder
    Json::FastWriter writer;
    return writer.write(payload);
}

bool ACMEClient::verifyJWS(const Json::Value& jws) {
    // TODO: Implement JWS verification
    return true;
}

std::string ACMEClient::extractCNFromCSR(const std::string& csr_pem) {
    // TODO: Extract CN from CSR
    return "";
}

bool ACMEClient::validateCSR(const Json::Value& csr) {
    // TODO: Validate CSR format and content
    return true;
}

bool ACMEClient::createCSR(const std::string& common_name, std::string& csr_pem) {
    // Generate RSA key
    EVP_PKEY* key = generateRSAKey(2048);
    if (!key) {
        console::e("Failed to generate RSA key");
        return false;
    }

    // Create X.509 certificate request structure
    X509_REQ* req = X509_REQ_new();
    if (!req) {
        EVP_PKEY_free(key);
        console::e("Failed to create X509_REQ");
        return false;
    }

    // Set subject
    X509_NAME* name = X509_NAME_new();
    if (!name) {
        X509_REQ_free(req);
        EVP_PKEY_free(key);
        console::e("Failed to create X509_NAME");
        return false;
    }

    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(common_name.c_str()),
                               common_name.length(), -1, 0);

    X509_REQ_set_subject_name(req, name);
    X509_NAME_free(name);

    // Set public key
    if (X509_REQ_set_pubkey(req, key) != 1) {
        X509_REQ_free(req);
        EVP_PKEY_free(key);
        console::e("Failed to set public key in CSR");
        return false;
    }

    // Sign the request
    if (X509_REQ_sign(req, key, EVP_sha256()) != 1) {
        X509_REQ_free(req);
        EVP_PKEY_free(key);
        console::e("Failed to sign CSR");
        return false;
    }

    // Convert to PEM
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        X509_REQ_free(req);
        EVP_PKEY_free(key);
        console::e("Failed to create BIO");
        return false;
    }

    if (!PEM_write_bio_X509_REQ(bio, req)) {
        BIO_free(bio);
        X509_REQ_free(req);
        EVP_PKEY_free(key);
        console::e("Failed to write CSR to BIO");
        return false;
    }

    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    if (len > 0) {
        csr_pem = std::string(data, len);
    }

    BIO_free(bio);
    X509_REQ_free(req);
    EVP_PKEY_free(key);

    return !csr_pem.empty();
}

EVP_PKEY* ACMEClient::generateRSAKey(size_t key_size) {
    EVP_PKEY* key = EVP_PKEY_new();
    if (!key) {
        return nullptr;
    }

    RSA* rsa = RSA_new();
    if (!rsa) {
        EVP_PKEY_free(key);
        return nullptr;
    }

    BIGNUM* bn = BN_new();
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

X509* ACMEClient::generateX509(const std::string& common_name, EVP_PKEY* key, bool is_ca) {
    X509* cert = X509_new();
    if (!cert) {
        return nullptr;
    }

    // Set version
    X509_set_version(cert, 2);

    // Set serial number
    ASN1_INTEGER* serial = ASN1_INTEGER_new();
    if (!serial) {
        X509_free(cert);
        return nullptr;
    }

    if (RAND_bytes((unsigned char*)serial->data, serial->length) != 1) {
        ASN1_INTEGER_free(serial);
        X509_free(cert);
        return nullptr;
    }

    X509_set_serialNumber(cert, serial);
    ASN1_INTEGER_free(serial);

    // Set validity
    ASN1_TIME* not_before = ASN1_TIME_new();
    ASN1_TIME* not_after = ASN1_TIME_new();
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
    X509_NAME* name = X509_NAME_new();
    if (!name) {
        X509_free(cert);
        return nullptr;
    }

    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(common_name.c_str()),
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

void ACMEClient::addExtensions(X509* cert, const std::string& common_name, bool is_ca) {
    // Basic constraints
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints, is_ca ? "CA:TRUE" : "CA:FALSE");
    if (ext) {
        X509_add_ext(cert, ext, 0);
        X509_EXTENSION_free(ext);
    }

    // Key usage
    ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_key_usage, "digitalSignature,keyEncipherment");
    if (ext) {
        X509_add_ext(cert, ext, 1);
        X509_EXTENSION_free(ext);
    }

    // Subject alternative name
    std::string san = "DNS:" + common_name;
    ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, san.c_str());
    if (ext) {
        X509_add_ext(cert, ext, 2);
        X509_EXTENSION_free(ext);
    }
}

OM_uint32 ACMEClient::acquireCredentials(const std::string& principal, gss_cred_id_t* cred) {
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc name_buf;
    gss_name_t name = GSS_C_NO_NAME;

    name_buf.length = principal.length();
    name_buf.value = const_cast<char*>(principal.c_str());

    maj_stat = gss_import_name(&min_stat, &name_buf, GSS_C_NT_HOSTBASED_SERVICE, &name);
    if (maj_stat != GSS_S_COMPLETE) {
        return maj_stat;
    }

    maj_stat = gss_acquire_cred(&min_stat, name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_INITIATE, cred, nullptr, nullptr);

    gss_release_name(&min_stat, &name);

    return maj_stat;
}

OM_uint32 ACMEClient::initSecurityContext(const std::string& target_principal, gss_ctx_id_t* context, gss_cred_id_t client_cred) {
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc input_token;
    gss_buffer_desc output_token;
    gss_ctx_id_t* context_ptr = context;

    input_token.length = 0;
    input_token.value = nullptr;

    maj_stat = gss_init_sec_context(&min_stat, client_cred, context_ptr, GSS_C_NO_NAME, GSS_C_NO_OID, GSS_C_MUTUAL_FLAG, GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS, &input_token, nullptr, &output_token, nullptr, nullptr);

    return maj_stat;
}

OM_uint32 ACMEClient::wrapToken(gss_ctx_id_t context, const std::string& token, std::string& wrapped_token) {
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc input_token;
    gss_buffer_desc output_token;

    input_token.length = token.length();
    input_token.value = const_cast<char*>(token.c_str());

    maj_stat = gss_wrap(&min_stat, context, true, GSS_C_QOP_DEFAULT, &input_token, nullptr, &output_token);

    if (maj_stat == GSS_S_COMPLETE) {
        wrapped_token = std::string(static_cast<char*>(output_token.value), output_token.length);
        gss_release_buffer(&min_stat, &output_token);
    }

    return maj_stat;
}

OM_uint32 ACMEClient::unwrapToken(gss_ctx_id_t context, const std::string& wrapped_token, std::string& token) {
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc input_token;
    gss_buffer_desc output_token;

    input_token.length = wrapped_token.length();
    input_token.value = const_cast<char*>(wrapped_token.c_str());

    maj_stat = gss_unwrap(&min_stat, context, &input_token, &output_token, nullptr, nullptr);

    if (maj_stat == GSS_S_COMPLETE) {
        token = std::string(static_cast<char*>(output_token.value), output_token.length);
        gss_release_buffer(&min_stat, &output_token);
    }

    return maj_stat;
}

} // namespace acme
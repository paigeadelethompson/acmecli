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

#include "acme_server.hpp"
#include "Console.hpp"
#include "HTTPServer.hpp"
#include "KerberosAuth.hpp"
#include "certificate_manager.hpp"
#include "policy_manager.hpp"
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <thread>

namespace acme {

  ACMEServer::ACMEServer(const std::string &config_path)
      : config_path_(config_path), server_port_(8080), running_(false) {}

  ACMEServer::~ACMEServer() { stop(); }

  bool ACMEServer::initialize() {
    // Load configuration
    std::ifstream config_file(config_path_);
    if (!config_file.is_open()) {
      console::e("Error: Could not open config file: {}", config_path_);
      return false;
    }

    Json::Value config;
    config_file >> config;

    // Extract configuration values
    std::string policy_file =
        config.get("policy_file", "/etc/acmecli/policy.json").asString();
    std::string kdc_principal =
        config.get("kdc_principal", "acme/acme-server@REALM").asString();
    std::string kdc_keytab =
        config.get("kdc_keytab", "/etc/acmecli/acme-server.keytab").asString();

    // Initialize components
    policy_manager_ = std::make_unique<PolicyManager>(policy_file);
    kerberos_auth_ = std::make_unique<KerberosAuth>(kdc_principal, kdc_keytab);

    // Create necessary directories
    std::filesystem::create_directories("/etc/ssl");
    std::filesystem::create_directories("/etc/acmecli");

    // Initialize CA if needed
    if (!cert_manager_->initializeCA()) {
      console::e("Error: Failed to initialize CA");
      return false;
    }

    console::e("ACME Server initialized successfully");
    return true;
  }

  void ACMEServer::run() {
    console::e("ACME Server running");

    // Create and initialize HTTP server
    http_server_ =
        std::make_unique<HTTPServer>(server_port_, kdc_principal_, kdc_keytab_);
    if (!http_server_->initialize()) {
      console::e("Failed to initialize HTTP server");
      return;
    }

    // Register ACME routes
    http_server_->registerRoute(
        "/acme/new-nonce",
        [this](const std::string &method, const std::string &path,
               const std::string &body, std::string &response) {
          auto nonce = generateNonce();
          response = R"({"nonce": ")" + nonce + R"("})";
        });

    http_server_->registerRoute(
        "/acme/dir", [this](const std::string &method, const std::string &path,
                            const std::string &body, std::string &response) {
          auto dir = handleDirectory();
          response = dir.toStyledString();
        });

    // Register secure routes with Kerberos authentication
    http_server_->registerSecureRoute(
        "/acme/new-account",
        [this](const std::string &method, const std::string &path,
               const std::string &body, std::string &response) {
          Json::Value request;
          Json::Reader reader;
          if (reader.parse(body, request)) {
            auto result = handleNewAccount(request);
            response = result.toStyledString();
          } else {
            response = R"({"error": "Invalid JSON"})";
          }
        });

    http_server_->registerSecureRoute(
        "/acme/order",
        [this](const std::string &method, const std::string &path,
               const std::string &body, std::string &response) {
          // Extract order_id from path
          std::string order_id = path.substr(path.find_last_of('/') + 1);
          Json::Value request;
          Json::Reader reader;
          if (reader.parse(body, request)) {
            auto result = handleOrder(order_id, request);
            response = result.toStyledString();
          } else {
            response = R"({"error": "Invalid JSON"})";
          }
        });

    http_server_->registerSecureRoute(
        "/acme/finalize",
        [this](const std::string &method, const std::string &path,
               const std::string &body, std::string &response) {
          // Extract order_id from path
          std::string order_id = path.substr(path.find_last_of('/') + 1);
          Json::Value request;
          Json::Reader reader;
          if (reader.parse(body, request)) {
            auto result = handleFinalizeOrder(order_id, request);
            response = result.toStyledString();
          } else {
            response = R"({"error": "Invalid JSON"})";
          }
        });

    http_server_->registerSecureRoute(
        "/acme/cert", [this](const std::string &method, const std::string &path,
                             const std::string &body, std::string &response) {
          // Extract cert_id from path
          std::string cert_id = path.substr(path.find_last_of('/') + 1);
          Json::Value request;
          Json::Reader reader;
          if (reader.parse(body, request)) {
            auto result = handleCertificate(cert_id, request);
            response = result.toStyledString();
          } else {
            response = R"({"error": "Invalid JSON"})";
          }
        });

    http_server_->registerSecureRoute(
        "/acme/revoke-cert",
        [this](const std::string &method, const std::string &path,
               const std::string &body, std::string &response) {
          Json::Value request;
          Json::Reader reader;
          if (reader.parse(body, request)) {
            auto result = handleRevokeCertificate(request);
            response = result.toStyledString();
          } else {
            response = R"({"error": "Invalid JSON"})";
          }
        });

    // Start the HTTP server
    if (!http_server_->start()) {
      console::e("Failed to start HTTP server");
      return;
    }

    console::e("ACME Server listening on port {}", server_port_);
    console::e("Kerberos principal: {}", kdc_principal_);
    console::e("Policy file: {}", policy_file_path_);

    // Keep server running
    while (running_) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  }

  void ACMEServer::stop() {
    running_ = false;
    if (http_server_) {
      http_server_->stop();
    }
    console::e("ACME Server stopped");
  }

  Json::Value ACMEServer::handleDirectory() {
    Json::Value response;
    response["type"] = "directory";
    response["nextUpdate"] = "2026-07-09T00:00:00Z";
    response["meta"] = Json::Value();
    response["meta"]["termsOfService"] = "https://example.com/tos";
    response["meta"]["website"] = "https://example.com";
    response["meta"]["caaIdentity"] = "example.com";
    response["meta"]["externalAccountRequired"] = false;

    response["authorizations"] = "/acme/authz/";
    response["certificate"] = "/acme/cert/";
    response["challengeResource"] = "/acme/challenge/";
    response["newNonce"] = "/acme/new-nonce";
    response["newAccount"] = "/acme/new-account";
    response["newOrder"] = "/acme/new-order";
    response["order"] = "/acme/order/";
    response["revokeCert"] = "/acme/revoke-cert";
    response["renewalInfo"] = "/acme/renewal-info/";

    return response;
  }

  Json::Value ACMEServer::handleNewNonce() {
    Json::Value response;
    response["nonce"] = generateNonce();
    return response;
  }

  Json::Value ACMEServer::handleNewAccount(const Json::Value &request) {
    std::lock_guard<std::mutex> lock(accounts_mutex_);

    // Extract account details
    std::string contact = request["contact"][0].asString();
    bool terms_agreed = request["termsOfServiceAgreed"].asBool();

    if (!terms_agreed) {
      Json::Value error;
      error["type"] = "urn:ietf:params:acme:error:rejectedIdentifier";
      error["detail"] = "Terms of service must be agreed to";
      error["status"] = "invalid";
      return error;
    }

    // Generate account ID
    std::string account_id =
        "account_" + std::to_string(std::hash<std::string>{}(contact));

    // Store account
    accounts_[account_id] = contact;

    Json::Value response;
    response["status"] = "valid";
    response["contact"] = request["contact"];
    response["orders"] = "/acme/order/";
    response["id"] = account_id;
    response["certificate"] = "/acme/cert/" + account_id;

    return response;
  }

  Json::Value ACMEServer::handleAccount(const std::string &account_id,
                                        const Json::Value &request) {
    std::lock_guard<std::mutex> lock(accounts_mutex_);

    auto it = accounts_.find(account_id);
    if (it == accounts_.end()) {
      Json::Value error;
      error["type"] = "urn:ietf:params:acme:error:accountDoesNotExist";
      error["detail"] = "Account not found";
      error["status"] = "invalid";
      return error;
    }

    Json::Value response;
    response["status"] = "valid";
    response["contact"] = request["contact"];
    response["orders"] = "/acme/order/";
    response["id"] = account_id;
    response["certificate"] = "/acme/cert/" + account_id;

    return response;
  }

  Json::Value ACMEServer::handleNewOrder(const Json::Value &request) {
    std::lock_guard<std::mutex> lock(orders_mutex_);

    // Extract identifiers
    Json::Value identifiers = request["identifiers"];
    std::vector<std::string> dns_names;

    for (const auto &id : identifiers) {
      if (id["type"].asString() == "dns") {
        dns_names.push_back(id["value"].asString());
      }
    }

    // Generate order ID
    std::string order_id =
        "order_" +
        std::to_string(std::hash<std::string>{}(request.toStyledString()));

    // Store order
    Json::Value order;
    order["status"] = "pending";
    order["expires"] = "2026-07-10T00:00:00Z";
    order["identifiers"] = identifiers;
    order["authorizations"] = Json::Value();
    order["finalize"] = "/acme/order/" + order_id + "/finalize";
    order["certificate"] = "/acme/cert/" + order_id;

    orders_[order_id] = order;

    // Generate authorization URLs
    Json::Value authorizations;
    for (size_t i = 0; i < dns_names.size(); ++i) {
      std::string authz_id =
          "authz_" + std::to_string(std::hash<std::string>{}(dns_names[i]));
      std::string authz_url = "/acme/authz/" + authz_id;
      authorizations.append(authz_url);
    }
    order["authorizations"] = authorizations;

    Json::Value response;
    response["status"] = "pending";
    response["expires"] = order["expires"];
    response["identifiers"] = identifiers;
    response["authorizations"] = authorizations;
    response["finalize"] = order["finalize"];
    response["certificate"] = order["certificate"];
    response["id"] = order_id;

    return response;
  }

  Json::Value ACMEServer::handleOrder(const std::string &order_id,
                                      const Json::Value &request) {
    std::lock_guard<std::mutex> lock(orders_mutex_);

    auto it = orders_.find(order_id);
    if (it == orders_.end()) {
      Json::Value error;
      error["type"] = "urn:ietf:params:acme:error:orderNotReady";
      error["detail"] = "Order not found";
      error["status"] = "invalid";
      return error;
    }

    Json::Value order = it->second;

    // Check if order is ready for finalization
    if (request.isMember("finalize")) {
      order["status"] = "ready";
    }

    Json::Value response;
    response["status"] = order["status"];
    response["expires"] = order["expires"];
    response["identifiers"] = order["identifiers"];
    response["authorizations"] = order["authorizations"];
    response["finalize"] = order["finalize"];
    response["certificate"] = order["certificate"];
    response["id"] = order_id;

    return response;
  }

  Json::Value ACMEServer::handleFinalizeOrder(const std::string &order_id,
                                              const Json::Value &request) {
    std::lock_guard<std::mutex> lock(orders_mutex_);

    auto it = orders_.find(order_id);
    if (it == orders_.end()) {
      Json::Value error;
      error["type"] = "urn:ietf:params:acme:error:orderNotReady";
      error["detail"] = "Order not found";
      error["status"] = "invalid";
      return error;
    }

    Json::Value order = it->second;

    // Validate CSR
    if (!validateCSR(request["csr"])) {
      Json::Value error;
      error["type"] = "urn:ietf:params:acme:error:malformed";
      error["detail"] = "Invalid CSR";
      error["status"] = "invalid";
      return error;
    }

    // Extract CN from CSR
    std::string cn = extractCNFromCSR(request["csr"].asString());

    // Validate policy
    if (!validatePolicy("client", cn)) {
      Json::Value error;
      error["type"] = "urn:ietf:params:acme:error:rejectedIdentifier";
      error["detail"] = "Certificate request rejected by policy";
      error["status"] = "invalid";
      return error;
    }

    // Generate certificate
    std::string cert_id =
        "cert_" + std::to_string(std::hash<std::string>{}(order_id));
    bool success = generateCertificate(order_id, cn, request["csr"].asString());

    if (!success) {
      Json::Value error;
      error["type"] = "urn:ietf:params:acme:error:internalError";
      error["detail"] = "Failed to generate certificate";
      error["status"] = "invalid";
      return error;
    }

    // Retrieve certificate from storage
    auto cert_it = certificates_.find(cert_id);
    if (cert_it == certificates_.end()) {
      Json::Value error;
      error["type"] = "urn:ietf:params:acme:error:internalError";
      error["detail"] = "Certificate not found after generation";
      error["status"] = "invalid";
      return error;
    }

    // Update order status
    order["status"] = "valid";
    order["certificate"] = "/acme/cert/" + cert_id;

    Json::Value response;
    response["status"] = "valid";
    response["certificate"] = "/acme/cert/" + cert_id;

    return response;
  }

  Json::Value ACMEServer::handleCertificate(const std::string &cert_id,
                                            const Json::Value &request) {
    std::lock_guard<std::mutex> lock(certificates_mutex_);

    auto cert_it = certificates_.find(cert_id);
    if (cert_it == certificates_.end()) {
      Json::Value error;
      error["type"] = "urn:ietf:params:acme:error:certificateRevoked";
      error["detail"] = "Certificate not found";
      error["status"] = "invalid";
      return error;
    }

    Json::Value response;
    response["certificate"] = cert_it->second;

    return response;
  }

  Json::Value ACMEServer::handleRevokeCertificate(const Json::Value &request) {
    std::string cert_id = request["certificate"].asString();

    if (revokeCertificate(cert_id)) {
      Json::Value response;
      response["status"] = "valid";
      return response;
    }

    Json::Value error;
    error["type"] = "urn:ietf:params:acme:error:rejectedIdentifier";
    error["detail"] = "Failed to revoke certificate";
    error["status"] = "invalid";
    return error;
  }

  std::string ACMEServer::generateNonce() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(0, 0xFFFFFFFFFFFFFFFFULL);

    std::string nonce;
    nonce.resize(16);
    for (size_t i = 0; i < nonce.size(); ++i) {
      nonce[i] = static_cast<char>(dis(gen) & 0xFF);
    }

    return nonce;
  }

  std::string ACMEServer::generateJWS(const Json::Value &payload,
                                      const std::string &account_key) {
    // TODO: Implement JWS generation with account key
    // For now, return placeholder
    return "";
  }

  bool ACMEServer::verifyJWS(const Json::Value &jws, std::string &account_id) {
    // TODO: Implement JWS verification
    return false;
  }

  bool ACMEServer::validatePolicy(const std::string &principal,
                                  const std::string &cn) {
    return policy_manager_->validate(principal, cn);
  }

  bool ACMEServer::validateCSR(const Json::Value &csr) {
    // TODO: Validate CSR format and content
    return true;
  }

  std::string ACMEServer::extractCNFromCSR(const std::string &csr_pem) {
    // TODO: Extract CN from CSR
    return "";
  }

  bool ACMEServer::generateCertificate(const std::string &account_id,
                                       const std::string &cn,
                                       const std::string &csr_pem) {
    std::string cert_id =
        "cert_" + std::to_string(std::hash<std::string>{}(account_id + cn));

    // Generate certificate using CertificateManager
    bool success = cert_manager_->generateCertificate(cn, csr_pem);
    if (!success) {
      return false;
    }

    // Retrieve the generated certificate
    std::string cert_path = "/etc/ssl/" + cn + ".crt";
    std::ifstream cert_file(cert_path);
    if (!cert_file.good()) {
      return false;
    }

    std::stringstream buffer;
    buffer << cert_file.rdbuf();
    std::string cert_pem = buffer.str();

    // Store certificate
    certificates_[cert_id] = cert_pem;

    return true;
  }

  bool ACMEServer::revokeCertificate(const std::string &cert_id) {
    std::lock_guard<std::mutex> lock(certificates_mutex_);

    auto it = certificates_.find(cert_id);
    if (it == certificates_.end()) {
      return false;
    }

    // TODO: Implement certificate revocation
    certificates_.erase(it);
    return true;
  }

  OM_uint32 ACMEServer::acquireCredentials(const std::string &principal,
                                           gss_cred_id_t *cred) {
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc name_buf;
    gss_name_t name = GSS_C_NO_NAME;

    name_buf.length = principal.length();
    name_buf.value = const_cast<char *>(principal.c_str());

    maj_stat = gss_import_name(&min_stat, &name_buf, GSS_C_NT_HOSTBASED_SERVICE,
                               &name);
    if (maj_stat != GSS_S_COMPLETE) {
      return maj_stat;
    }

    maj_stat =
        gss_acquire_cred(&min_stat, name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                         GSS_C_ACCEPT, cred, nullptr, nullptr);

    gss_release_name(&min_stat, &name);

    return maj_stat;
  }

  OM_uint32 ACMEServer::acceptSecurityContext(gss_ctx_id_t *context,
                                              gss_cred_id_t server_cred) {
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc input_token;
    gss_buffer_desc output_token;
    gss_ctx_id_t *context_ptr = context;

    input_token.length = 0;
    input_token.value = nullptr;

    OM_uint32 ret_flags = 0;
    OM_uint32 time_rec = 0;
    gss_cred_id_t delegated_cred = GSS_C_NO_CREDENTIAL;
    gss_OID mech_type = GSS_C_NO_OID;
    maj_stat = gss_accept_sec_context(&min_stat, context_ptr, server_cred,
                                      &input_token, GSS_C_NO_CHANNEL_BINDINGS,
                                      nullptr, &mech_type, &output_token,
                                      &ret_flags, &time_rec, &delegated_cred);

    return maj_stat;
  }

  OM_uint32 ACMEServer::verifyToken(gss_ctx_id_t context,
                                    const std::string &token,
                                    std::string &principal) {
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc input_token;
    gss_buffer_desc output_token;
    gss_name_t client_name = GSS_C_NO_NAME;

    input_token.length = token.length();
    input_token.value = const_cast<char *>(token.c_str());

    OM_uint32 ret_flags = 0;
    OM_uint32 time_rec = 0;
    gss_cred_id_t delegated_cred = GSS_C_NO_CREDENTIAL;
    gss_OID mech_type = GSS_C_NO_OID;
    maj_stat = gss_accept_sec_context(&min_stat, &context, GSS_C_NO_CREDENTIAL,
                                      &input_token, GSS_C_NO_CHANNEL_BINDINGS,
                                      &client_name, &mech_type, &output_token,
                                      &ret_flags, &time_rec, &delegated_cred);

    if (maj_stat == GSS_S_COMPLETE) {
      gss_buffer_desc name_buf;
      gss_display_name(&min_stat, client_name, &name_buf, nullptr);
      principal =
          std::string(static_cast<char *>(name_buf.value), name_buf.length);
      gss_release_buffer(&min_stat, &name_buf);
    }

    gss_release_name(&min_stat, &client_name);

    return maj_stat;
  }

  void ACMEServer::cleanupGSS(gss_ctx_id_t context, gss_cred_id_t cred) {
    OM_uint32 maj_stat, min_stat;

    if (context != GSS_C_NO_CONTEXT) {
      gss_delete_sec_context(&min_stat, &context, GSS_C_NO_BUFFER);
    }

    if (cred != GSS_C_NO_CREDENTIAL) {
      gss_release_cred(&min_stat, &cred);
    }
  }

} // namespace acme
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

#include "HTTPServer.hpp"
#include "Console.hpp"
#include "KerberosAuth.hpp"
#include <chrono>
#include <fstream>
#include <sstream>
#include <thread>

namespace acme {

  HTTPServer::HTTPServer(int port, const std::string &principal,
                         const std::string &keytab_path)
      : port_(port), principal_(principal), keytab_path_(keytab_path),
        server_cred_(GSS_C_NO_CREDENTIAL), context_(GSS_C_NO_CONTEXT),
        running_(false) {}

  HTTPServer::~HTTPServer() { stop(); }

  bool HTTPServer::initialize() {
    // Initialize Kerberos credentials
    KerberosAuth kerberos(principal_, keytab_path_);
    if (!kerberos.initialize()) {
      last_error_ = "Failed to initialize Kerberos authentication";
      return false;
    }

    // Acquire server credentials
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc name_buf;
    gss_name_t name = GSS_C_NO_NAME;

    name_buf.length = principal_.length();
    name_buf.value = const_cast<char *>(principal_.c_str());

    maj_stat = gss_import_name(&min_stat, &name_buf, GSS_C_NT_HOSTBASED_SERVICE,
                               &name);
    if (maj_stat != GSS_S_COMPLETE) {
      last_error_ = "Failed to import GSSAPI name";
      return false;
    }

    maj_stat =
        gss_acquire_cred(&min_stat, name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                         GSS_C_ACCEPT, &server_cred_, nullptr, nullptr);

    gss_release_name(&min_stat, &name);

    if (maj_stat != GSS_S_COMPLETE) {
      last_error_ = "Failed to acquire GSSAPI credentials";
      return false;
    }

    console::i("HTTPServer initialized on port {}", port_);
    return true;
  }

  bool HTTPServer::start() {
    if (server_cred_ == GSS_C_NO_CREDENTIAL) {
      last_error_ = "Server not initialized";
      return false;
    }

    running_ = true;

    // Start server thread
    server_thread_ = std::thread(&HTTPServer::serverLoop, this);

    console::i("HTTPServer started on port {}", port_);
    return true;
  }

  void HTTPServer::stop() {
    running_ = false;
    if (server_thread_.joinable()) {
      server_thread_.join();
    }
    console::i("HTTPServer stopped");
  }

  void HTTPServer::registerRoute(
      const std::string &path,
      std::function<void(const std::string &, const std::string &,
                         const std::string &, std::string &)>
          handler) {
    routes_[path] = handler;
    console::i("Registered route: {}", path);
  }

  void HTTPServer::registerSecureRoute(
      const std::string &path,
      std::function<void(const std::string &, const std::string &,
                         const std::string &, std::string &)>
          handler) {
    secure_routes_[path] = handler;
    console::i("Registered secure route: {}", path);
  }

  int HTTPServer::getPort() const { return port_; }

  std::string HTTPServer::getLastError() const { return last_error_; }

  void HTTPServer::handleRequest(
      const std::string &request_line,
      const std::unordered_map<std::string, std::string> &headers,
      const std::string &body, std::string &response) {
    std::string method, path, version;
    if (!parseRequestLine(request_line, method, path, version)) {
      response = buildErrorResponse(400, "Bad Request");
      return;
    }

    console::i("Received {} request for {}", method, path);

    // Check if this is a secure route
    auto it = secure_routes_.find(path);
    if (it != secure_routes_.end()) {
      // Extract Authorization header
      std::string auth_header;
      auto auth_it = headers.find("Authorization");
      if (auth_it != headers.end()) {
        auth_header = auth_it->second;
      }

      // Handle Kerberos authentication
      std::string principal;
      if (!handleKerberosAuth(auth_header, principal)) {
        response = buildErrorResponse(401, "Unauthorized");
        return;
      }

      console::i("Authenticated principal: {}", principal);

      // Call the handler
      it->second(method, path, body, response);
      return;
    }

    // Check if this is a regular route
    auto route_it = routes_.find(path);
    if (route_it != routes_.end()) {
      route_it->second(method, path, body, response);
      return;
    }

    // Handle ACME-specific endpoints
    if (path == "/acme/new-nonce") {
      response = buildJsonResponse(200, R"({"nonce": "random-nonce-value"})");
      return;
    }

    if (path == "/acme/dir") {
      response = buildJsonResponse(200, R"({
        "type": "directory",
        "nextUpdate": "2026-07-09T00:00:00Z",
        "meta": {
          "termsOfService": "https://example.com/tos",
          "website": "https://example.com",
          "caaIdentity": "example.com",
          "externalAccountRequired": false
        },
        "authorizations": "/acme/authz/",
        "certificate": "/acme/cert/",
        "challengeResource": "/acme/challenge/",
        "newNonce": "/acme/new-nonce",
        "newAccount": "/acme/new-account",
        "newOrder": "/acme/new-order",
        "order": "/acme/order/",
        "revokeCert": "/acme/revoke-cert",
        "renewalInfo": "/acme/renewal-info/"
      })");
      return;
    }

    // Default 404 response
    response = buildErrorResponse(404, "Not Found");
  }

  bool HTTPServer::parseRequestLine(const std::string &request_line,
                                    std::string &method, std::string &path,
                                    std::string &version) {
    size_t space1 = request_line.find(' ');
    size_t space2 = request_line.find(' ', space1 + 1);

    if (space1 == std::string::npos || space2 == std::string::npos) {
      return false;
    }

    method = request_line.substr(0, space1);
    path = request_line.substr(space1 + 1, space2 - space1 - 1);
    version = request_line.substr(space2 + 1);

    return true;
  }

  std::unordered_map<std::string, std::string>
  HTTPServer::parseHeaders(const std::string &headers_str) {
    std::unordered_map<std::string, std::string> headers;
    std::stringstream ss(headers_str);
    std::string line;

    while (std::getline(ss, line)) {
      size_t colon = line.find(':');
      if (colon != std::string::npos) {
        std::string name = line.substr(0, colon);
        std::string value = line.substr(colon + 2); // Skip ": "
        headers[name] = value;
      }
    }

    return headers;
  }

  std::string HTTPServer::buildResponseHeaders(int status_code,
                                               const std::string &content_type,
                                               size_t content_length) {
    std::stringstream ss;
    ss << "HTTP/1.1 " << status_code << " OK\r\n";
    ss << "Content-Type: " << content_type << "\r\n";
    ss << "Content-Length: " << content_length << "\r\n";
    ss << "Connection: close\r\n";
    ss << "\r\n";
    return ss.str();
  }

  bool HTTPServer::handleKerberosAuth(const std::string &auth_header,
                                      std::string &principal) {
    if (auth_header.empty()) {
      last_error_ = "No Authorization header provided";
      return false;
    }

    // Parse Authorization header (e.g., "Negotiate <token>")
    if (auth_header.find("Negotiate ") != 0) {
      last_error_ = "Invalid Authorization header format";
      return false;
    }

    std::string token = auth_header.substr(10);

    // For now, we'll do basic validation
    // In production, you would use GSSAPI to verify the token
    if (token.empty()) {
      last_error_ = "Empty GSSAPI token";
      return false;
    }

    // TODO: Implement actual GSSAPI token verification
    // This is a placeholder
    principal = "test-user@REALM";
    return true;
  }

  bool HTTPServer::verifyJWSSignature(const std::string &body,
                                      const std::string &signature) {
    // TODO: Implement JWS signature verification
    // This would use the GSSAPI context to verify the signature
    console::i("Verifying JWS signature");
    return true;
  }

  void HTTPServer::serverLoop() {
    // TODO: Implement actual HTTP server loop
    // This would use a socket to listen for incoming connections
    // For now, we'll just sleep until stopped
    while (running_) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    console::i("Server loop exited");
  }

  std::string HTTPServer::buildJsonResponse(int status_code,
                                            const std::string json_body) {
    std::string response = buildResponseHeaders(status_code, "application/json",
                                                json_body.length());
    response += json_body;
    return response;
  }

  std::string HTTPServer::buildErrorResponse(int status_code,
                                             const std::string message) {
    std::string error_json =
        R"({"type": "error", "detail": ")" + message + "\"}";
    return buildJsonResponse(status_code, error_json);
  }

} // namespace acme
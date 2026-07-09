#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <functional>
#include <thread>
#include <gssapi/gssapi.h>

namespace acme {

  class HTTPServer {
  public:
    /**
     * @brief Constructor
     * @param port Port to listen on
     * @param principal Kerberos principal for server authentication
     * @param keytab_path Path to keytab file
     */
    HTTPServer(int port, const std::string &principal,
               const std::string &keytab_path);

    /**
     * @brief Destructor
     */
    ~HTTPServer();

    /**
     * @brief Initialize the HTTP server
     * @return true if initialization successful
     */
    bool initialize();

    /**
     * @brief Start the HTTP server
     * @return true if server started successfully
     */
    bool start();

    /**
     * @brief Stop the HTTP server
     */
    void stop();

    /**
     * @brief Register a route handler
     * @param path Route path (e.g., "/acme/new-nonce")
     * @param handler Handler function
     */
    void registerRoute(const std::string &path,
                       std::function<void(const std::string &, const std::string &,
                                         const std::string &, std::string &)>
                           handler);

    /**
     * @brief Register a route handler with Kerberos authentication
     * @param path Route path
     * @param handler Handler function
     */
    void registerSecureRoute(const std::string &path,
                             std::function<void(const std::string &, const std::string &,
                                               const std::string &, std::string &)>
                                 handler);

    /**
     * @brief Get the server port
     * @return Port number
     */
    int getPort() const;

    /**
     * @brief Get the last error message
     * @return Error message
     */
    std::string getLastError() const;

  private:
    /**
     * @brief Handle incoming HTTP request
     * @param request_line Request line (e.g., "GET /acme/new-nonce HTTP/1.1")
     * @param headers Request headers
     * @param body Request body
     * @param response Response body
     */
    void handleRequest(const std::string &request_line,
                       const std::unordered_map<std::string, std::string> &headers,
                       const std::string &body, std::string &response);

    /**
     * @brief Parse request line
     * @param request_line Request line
     * @param method HTTP method
     * @param path Request path
     * @param version HTTP version
     * @return true if parsing successful
     */
    bool parseRequestLine(const std::string &request_line, std::string &method,
                          std::string &path, std::string &version);

    /**
     * @brief Parse headers
     * @param headers_str Headers string
     * @return Map of headers
     */
    std::unordered_map<std::string, std::string> parseHeaders(
        const std::string &headers_str);

    /**
     * @brief Build response headers
     * @param status_code HTTP status code
     * @param content_type Content type
     * @param content_length Content length
     * @return Response headers string
     */
    std::string buildResponseHeaders(int status_code,
                                     const std::string &content_type,
                                     size_t content_length);

    /**
     * @brief Handle Kerberos authentication
     * @param auth_header Authorization header value
     * @param principal Output principal name
     * @return true if authentication successful
     */
    bool handleKerberosAuth(const std::string &auth_header,
                            std::string &principal);

    /**
     * @brief Verify JWS signature
     * @param body Request body
     * @param signature Signature from header
     * @return true if signature valid
     */
    bool verifyJWSSignature(const std::string &body,
                            const std::string &signature);

    int port_;
    std::string principal_;
    std::string keytab_path_;
    gss_cred_id_t server_cred_;
    gss_ctx_id_t context_;

    std::unordered_map<std::string, std::function<void(const std::string &,
                                                        const std::string &,
                                                        const std::string &,
                                                        std::string &)>>
        routes_;
    std::unordered_map<std::string,
                       std::function<void(const std::string &, const std::string &,
                                         const std::string &, std::string &)>>
        secure_routes_;

    bool running_;
    std::string last_error_;
    std::thread server_thread_;

    void serverLoop();
    std::string buildJsonResponse(int status_code, const std::string json_body);
    std::string buildErrorResponse(int status_code, const std::string message);
  };

} // namespace acme
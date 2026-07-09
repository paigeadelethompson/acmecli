#pragma once

#include <string>
#include <memory>
#include <vector>
#include <map>
#include <functional>

#include <gssapi/gssapi.h>

namespace acme {

class Request;
class Response;

/**
 * @brief HTTP Client class with GSSAPI/Kerberos authentication support
 * 
 * This class provides a high-level interface for making HTTP requests
 * with support for Kerberos/GSSAPI authentication.
 */
class HTTPClient {
public:
    /**
     * @brief Constructor
     * @param principal Kerberos principal for authentication (optional)
     * @param keytab_path Path to keytab file for service principal (optional)
     */
    explicit HTTPClient(const std::string& principal = "", 
                       const std::string& keytab_path = "");
    
    /**
     * @brief Destructor
     */
    ~HTTPClient();
    
    /**
     * @brief Initialize Kerberos authentication
     * @return true if initialization successful
     */
    bool initialize();
    
    /**
     * @brief Make a GET request
     * @param url Request URL
     * @param response Response object to populate
     * @return true if request successful
     */
    bool get(const std::string& url, Response& response);
    
    /**
     * @brief Make a POST request
     * @param url Request URL
     * @param body Request body
     * @param response Response object to populate
     * @return true if request successful
     */
    bool post(const std::string& url, const std::string& body, Response& response);
    
    /**
     * @brief Make a PUT request
     * @param url Request URL
     * @param body Request body
     * @param response Response object to populate
     * @return true if request successful
     */
    bool put(const std::string& url, const std::string& body, Response& response);
    
    /**
     * @brief Make a DELETE request
     * @param url Request URL
     * @param response Response object to populate
     * @return true if request successful
     */
    bool del(const std::string& url, Response& response);
    
    /**
     * @brief Set custom headers
     * @param headers Map of header name to value
     */
    void setHeaders(const std::map<std::string, std::string>& headers);
    
    /**
     * @brief Add a single header
     * @param name Header name
     * @param value Header value
     */
    void addHeader(const std::string& name, const std::string& value);
    
    /**
     * @brief Set timeout in seconds
     * @param timeout Timeout in seconds
     */
    void setTimeout(int timeout);
    
    /**
     * @brief Set user agent string
     * @param userAgent User agent string
     */
    void setUserAgent(const std::string& userAgent);
    
    /**
     * @brief Get the last error message
     * @return Error message
     */
    std::string getLastError() const;
    
    /**
     * @brief Check if client is initialized
     * @return true if initialized
     */
    bool isInitialized() const;
    
    /**
     * @brief Get the Kerberos principal
     * @return Principal string
     */
    std::string getPrincipal() const;
    
    /**
     * @brief Get the GSSAPI context
     * @return GSSAPI context handle
     */
    gss_ctx_id_t getContext() const;

private:
    /**
     * @brief Create request object
     * @param method HTTP method
     * @param url Request URL
     * @return Request object
     */
    std::unique_ptr<Request> createRequest(const std::string& method, 
                                          const std::string& url);
    
    /**
     * @brief Perform GSSAPI authentication
     * @param request Request object
     * @return true if authentication successful
     */
    bool performGSSAuth(Request& request);
    
    /**
     * @brief Cleanup GSSAPI resources
     */
    void cleanupGSS();
    
    /**
     * @brief Parse response from fetch API
     * @param response Response object to populate
     * @param file Pointer to file from fetch API
     */
    void parseResponse(Response& response, FILE* file);
    
    std::string principal_;
    std::string keytab_path_;
    gss_cred_id_t credentials_;
    gss_ctx_id_t context_;
    
    std::map<std::string, std::string> headers_;
    std::string user_agent_;
    int timeout_;
    
    std::string last_error_;
    bool initialized_;
};

/**
 * @brief HTTP Request class
 */
class Request {
public:
    enum class Method {
        GET,
        POST,
        PUT,
        DELETE,
        HEAD,
        OPTIONS
    };
    
    /**
     * @brief Constructor
     * @param method HTTP method
     * @param url Request URL
     */
    Request(Method method, const std::string& url);
    
    /**
     * @brief Destructor
     */
    ~Request();
    
    /**
     * @brief Set request body
     * @param body Request body
     */
    void setBody(const std::string& body);
    
    /**
     * @brief Set content type header
     * @param contentType Content type string
     */
    void setContentType(const std::string& contentType);
    
    /**
     * @brief Set accept header
     * @param accept Accept header string
     */
    void setAccept(const std::string& accept);
    
    /**
     * @brief Add custom header
     * @param name Header name
     * @param value Header value
     */
    void addHeader(const std::string& name, const std::string& value);
    
    /**
     * @brief Get HTTP method as string
     * @return Method string
     */
    std::string getMethodString() const;
    
    /**
     * @brief Get the request URL
     * @return URL string
     */
    std::string getUrl() const;
    
    /**
     * @brief Get the request body
     * @return Body string
     */
    std::string getBody() const;
    
    /**
     * @brief Get all headers
     * @return Map of headers
     */
    const std::map<std::string, std::string>& getHeaders() const;
    
    /**
     * @brief Get the HTTP method enum
     * @return Method enum
     */
    Method getMethod() const;
    
    /**
     * @brief Get the request body size
     * @return Body size
     */
    size_t getBodySize() const;

private:
    Method method_;
    std::string url_;
    std::string body_;
    std::string content_type_;
    std::string accept_;
    std::map<std::string, std::string> headers_;
};

/**
 * @brief HTTP Response class
 */
class Response {
public:
    /**
     * @brief Constructor
     */
    Response();
    
    /**
     * @brief Destructor
     */
    ~Response();
    
    /**
     * @brief Get HTTP status code
     * @return Status code
     */
    int getStatusCode() const;
    
    /**
     * @brief Get response headers
     * @return Map of headers
     */
    const std::map<std::string, std::string>& getHeaders() const;
    
    /**
     * @brief Get response body
     * @return Body string
     */
    std::string getBody() const;
    
    /**
     * @brief Get the body as a string
     * @return Body string
     */
    std::string toString() const;
    
    /**
     * @brief Check if response was successful
     * @return true if status code is 2xx
     */
    bool isSuccessful() const;
    
    /**
     * @brief Check if response is a redirect
     * @return true if status code is 3xx
     */
    bool isRedirect() const;
    
    /**
     * @brief Get the content type
     * @return Content type string
     */
    std::string getContentType() const;
    
    /**
     * @brief Get the content length
     * @return Content length
     */
    size_t getContentLength() const;
    
    /**
     * @brief Get the last error message
     * @return Error message
     */
    std::string getLastError() const;
    
    /**
     * @brief Get the response time in milliseconds
     * @return Response time
     */
    long getResponseTime() const;
    
    /**
     * @brief Get the URL that was requested
     * @return URL string
     */
    std::string getUrl() const;
    
    /**
     * @brief Get the effective URL (after redirects)
     * @return Effective URL string
     */
    std::string getEffectiveUrl() const;

private:
    int status_code_;
    std::map<std::string, std::string> headers_;
    std::string body_;
    std::string content_type_;
    size_t content_length_;
    std::string last_error_;
    long response_time_;
    std::string url_;
    std::string effective_url_;
};

} // namespace acme
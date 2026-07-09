#pragma once

#include <string>
#include <map>

namespace acme {

/**
 * @brief HTTP Request class
 * 
 * Represents an HTTP request with method, URL, headers, and body.
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
    size_t content_length_;
};

} // namespace acme
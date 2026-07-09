#pragma once

#include <chrono>
#include <map>
#include <string>

namespace acme {

  /**
   * @brief HTTP Response class
   *
   * Represents an HTTP response with status code, headers, and body.
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
    const std::map<std::string, std::string> &getHeaders() const;

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

    // Setters
    void setStatusCode(int code);
    void addHeader(const std::string &name, const std::string &value);
    void setBody(const std::string &body);
    void setUrl(const std::string &url);
    void setResponseTime(long time);
    void setEffectiveUrl(const std::string &url);
    void setLastError(const std::string &error);

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
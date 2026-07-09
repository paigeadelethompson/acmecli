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

#include <map>
#include <string>

namespace acme {

  /**
   * @brief HTTP Request class
   *
   * Represents an HTTP request with method, URL, headers, and body.
   */
  class Request {
  public:
    enum class Method { GET, POST, PUT, DELETE, HEAD, OPTIONS };

    /**
     * @brief Constructor
     * @param method HTTP method
     * @param url Request URL
     */
    Request(Method method, const std::string &url);

    /**
     * @brief Destructor
     */
    ~Request();

    /**
     * @brief Set request body
     * @param body Request body
     */
    void setBody(const std::string &body);

    /**
     * @brief Set content type header
     * @param contentType Content type string
     */
    void setContentType(const std::string &contentType);

    /**
     * @brief Set accept header
     * @param accept Accept header string
     */
    void setAccept(const std::string &accept);

    /**
     * @brief Add custom header
     * @param name Header name
     * @param value Header value
     */
    void addHeader(const std::string &name, const std::string &value);

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
    const std::map<std::string, std::string> &getHeaders() const;

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
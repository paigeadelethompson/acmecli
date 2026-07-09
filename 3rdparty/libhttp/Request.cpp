#include "Request.hpp"

namespace acme {

Request::Request(Method method, const std::string& url)
    : method_(method), url_(url), content_length_(0) {
}

Request::~Request() = default;

void Request::setBody(const std::string& body) {
    body_ = body;
    content_length_ = body.length();
}

void Request::setContentType(const std::string& contentType) {
    content_type_ = contentType;
    addHeader("Content-Type", contentType);
}

void Request::setAccept(const std::string& accept) {
    accept_ = accept;
    addHeader("Accept", accept);
}

void Request::addHeader(const std::string& name, const std::string& value) {
    headers_[name] = value;
}

std::string Request::getMethodString() const {
    switch (method_) {
        case Method::GET: return "GET";
        case Method::POST: return "POST";
        case Method::PUT: return "PUT";
        case Method::DELETE: return "DELETE";
        case Method::HEAD: return "HEAD";
        case Method::OPTIONS: return "OPTIONS";
        default: return "GET";
    }
}

std::string Request::getUrl() const {
    return url_;
}

std::string Request::getBody() const {
    return body_;
}

const std::map<std::string, std::string>& Request::getHeaders() const {
    return headers_;
}

Request::Method Request::getMethod() const {
    return method_;
}

size_t Request::getBodySize() const {
    return content_length_;
}

} // namespace acme
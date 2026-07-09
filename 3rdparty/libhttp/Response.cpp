#include "Response.hpp"
#include <sstream>

namespace acme {

Response::Response()
    : status_code_(0), content_length_(0), response_time_(0) {
}

Response::~Response() = default;

int Response::getStatusCode() const {
    return status_code_;
}

const std::map<std::string, std::string>& Response::getHeaders() const {
    return headers_;
}

std::string Response::getBody() const {
    return body_;
}

std::string Response::toString() const {
    return body_;
}

bool Response::isSuccessful() const {
    return status_code_ >= 200 && status_code_ < 300;
}

bool Response::isRedirect() const {
    return status_code_ >= 300 && status_code_ < 400;
}

std::string Response::getContentType() const {
    return content_type_;
}

size_t Response::getContentLength() const {
    return content_length_;
}

std::string Response::getLastError() const {
    return last_error_;
}

long Response::getResponseTime() const {
    return response_time_;
}

std::string Response::getUrl() const {
    return url_;
}

std::string Response::getEffectiveUrl() const {
    return effective_url_;
}

void Response::setStatusCode(int code) {
    status_code_ = code;
}

void Response::addHeader(const std::string& name, const std::string& value) {
    headers_[name] = value;
    
    if (name == "Content-Type") {
        content_type_ = value;
    }
    if (name == "Content-Length") {
        content_length_ = std::stoul(value);
    }
}

void Response::setBody(const std::string& body) {
    body_ = body;
}

void Response::setUrl(const std::string& url) {
    url_ = url;
}

void Response::setResponseTime(long time) {
    response_time_ = time;
}

void Response::setEffectiveUrl(const std::string& url) {
    effective_url_ = url;
}

void Response::setLastError(const std::string& error) {
    last_error_ = error;
}

} // namespace acme
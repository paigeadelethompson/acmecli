#include "HTTPClient.hpp"
#include "console.hpp"
#include <fstream>
#include <sstream>
#include <chrono>
#include <cstring>
#include <sys/param.h>

#ifdef HAVE_LIBFETCH
#include <fetch.h>
#else
#include <curl/curl.h>
#endif

namespace acme {

// ============================================================================
// HTTPClient Implementation
// ============================================================================

HTTPClient::HTTPClient(const std::string& principal, const std::string& keytab_path)
    : principal_(principal),
      keytab_path_(keytab_path),
      credentials_(GSS_C_NO_CREDENTIAL),
      context_(GSS_C_NO_CONTEXT),
      timeout_(30),
      user_agent_("acmecli/1.0"),
      initialized_(false) {
}

HTTPClient::~HTTPClient() {
    cleanupGSS();
}

bool HTTPClient::initialize() {
    if (principal_.empty()) {
        last_error_ = "No Kerberos principal specified";
        return false;
    }

    // Initialize GSSAPI credentials
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc name_buf;
    gss_name_t name = GSS_C_NO_NAME;

    name_buf.length = principal_.length();
    name_buf.value = const_cast<char*>(principal_.c_str());

    maj_stat = gss_import_name(&min_stat, &name_buf, GSS_C_NT_HOSTBASED_SERVICE, &name);
    
    if (maj_stat != GSS_S_COMPLETE) {
        last_error_ = "Failed to import GSSAPI name";
        return false;
    }

    maj_stat = gss_acquire_cred(&min_stat, name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                                GSS_C_INITIATE, &credentials_, NULL, NULL);

    gss_release_name(&min_stat, &name);

    if (maj_stat != GSS_S_COMPLETE) {
        last_error_ = "Failed to acquire GSSAPI credentials";
        return false;
    }

    initialized_ = true;
    console::i("HTTPClient initialized with principal: {}", principal_);
    return true;
}

bool HTTPClient::get(const std::string& url, Response& response) {
    auto request = createRequest("GET", url);
    return performRequest(*request, response);
}

bool HTTPClient::post(const std::string& url, const std::string& body, Response& response) {
    auto request = createRequest("POST", url);
    request->setBody(body);
    request->setContentType("application/json");
    return performRequest(*request, response);
}

bool HTTPClient::put(const std::string& url, const std::string& body, Response& response) {
    auto request = createRequest("PUT", url);
    request->setBody(body);
    request->setContentType("application/json");
    return performRequest(*request, response);
}

bool HTTPClient::del(const std::string& url, Response& response) {
    auto request = createRequest("DELETE", url);
    return performRequest(*request, response);
}

void HTTPClient::setHeaders(const std::map<std::string, std::string>& headers) {
    headers_ = headers;
}

void HTTPClient::addHeader(const std::string& name, const std::string& value) {
    headers_[name] = value;
}

void HTTPClient::setTimeout(int timeout) {
    timeout_ = timeout;
}

void HTTPClient::setUserAgent(const std::string& userAgent) {
    user_agent_ = userAgent;
}

std::string HTTPClient::getLastError() const {
    return last_error_;
}

bool HTTPClient::isInitialized() const {
    return initialized_;
}

std::string HTTPClient::getPrincipal() const {
    return principal_;
}

gss_ctx_id_t HTTPClient::getContext() const {
    return context_;
}

std::unique_ptr<Request> HTTPClient::createRequest(const std::string& method, const std::string& url) {
    return std::make_unique<Request>(Request::Method::GET, url);
}

bool HTTPClient::performGSSAuth(Request& request) {
    if (!initialized_ || credentials_ == GSS_C_NO_CREDENTIAL) {
        last_error_ = "HTTPClient not initialized or no credentials";
        return false;
    }

    // For now, we'll use the GSSAPI context if available
    // In a real implementation, you would perform SPNEGO authentication
    // and add the appropriate Authorization header
    
    // Example: Add GSSAPI token to headers
    // request.addHeader("Authorization", "Negotiate " + gss_token);
    
    return true;
}

bool HTTPClient::performRequest(Request& request, Response& response) {
    if (!initialized_) {
        last_error_ = "HTTPClient not initialized";
        return false;
    }

    auto start_time = std::chrono::high_resolution_clock::now();

#ifdef HAVE_LIBFETCH
    // Use libfetch
    FILE* file = nullptr;
    struct url_stat stat;
    struct url* url_struct = fetchParseURL(request.getUrl().c_str());
    
    if (!url_struct) {
        last_error_ = "Failed to parse URL";
        return false;
    }

    // Set timeout
    fetchTimeout = timeout_;

    // Perform request based on method
    switch (request.getMethod()) {
        case Request::Method::GET:
            file = fetchXGetHTTP(url_struct, &stat, nullptr);
            break;
        case Request::Method::POST:
            file = fetchPutHTTP(url_struct, request.getBody().c_str());
            break;
        case Request::Method::PUT:
            file = fetchPutHTTP(url_struct, request.getBody().c_str());
            break;
        case Request::Method::DELETE:
            file = fetchXGetHTTP(url_struct, &stat, nullptr);
            break;
        default:
            file = fetchXGetHTTP(url_struct, &stat, nullptr);
            break;
    }

    fetchFreeURL(url_struct);

    if (!file) {
        last_error_ = fetchLastErrString;
        return false;
    }

    parseResponse(response, file);
    fclose(file);

#else
    // Use libcurl as fallback
    CURL* curl = curl_easy_init();
    if (!curl) {
        last_error_ = "Failed to initialize libcurl";
        return false;
    }

    // Set URL
    curl_easy_setopt(curl, CURLOPT_URL, request.getUrl().c_str());

    // Set method
    switch (request.getMethod()) {
        case Request::Method::GET:
            curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
            break;
        case Request::Method::POST:
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.getBody().c_str());
            break;
        case Request::Method::PUT:
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.getBody().c_str());
            break;
        case Request::Method::DELETE:
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
            break;
        default:
            curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
            break;
    }

    // Set headers
    struct curl_slist* headers = nullptr;
    for (const auto& [name, value] : request.getHeaders()) {
        std::string header = name + ": " + value;
        headers = curl_slist_append(headers, header.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Set user agent
    curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent_.c_str());

    // Set timeout
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_);

    // Set write callback
    std::string response_buffer;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, [](void* contents, size_t size, size_t nmemb, void* userp) {
        std::string* str = static_cast<std::string*>(userp);
        str->append(static_cast<char*>(contents), size * nmemb);
        return size * nmemb;
    });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_buffer);

    // Perform request
    CURLcode res = curl_easy_perform(curl);

    // Cleanup
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        last_error_ = curl_easy_strerror(res);
        return false;
    }

    // Parse response
    response.setBody(response_buffer);
    response.setUrl(request.getUrl());
#endif

    auto end_time = std::chrono::high_resolution_clock::now();
    response.setResponseTime(std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time).count());

    return true;
}

void HTTPClient::cleanupGSS() {
    if (context_ != GSS_C_NO_CONTEXT) {
        OM_uint32 maj_stat, min_stat;
        maj_stat = gss_delete_sec_context(&min_stat, &context_, GSS_C_NO_BUFFER);
        context_ = GSS_C_NO_CONTEXT;
    }

    if (credentials_ != GSS_C_NO_CREDENTIAL) {
        OM_uint32 maj_stat, min_stat;
        maj_stat = gss_release_cred(&min_stat, &credentials_);
        credentials_ = GSS_C_NO_CREDENTIAL;
    }
}

void HTTPClient::parseResponse(Response& response, FILE* file) {
    // Read headers
    char line[4096];
    while (fgets(line, sizeof(line), file)) {
        std::string line_str(line);
        if (line_str.find("HTTP/") == 0) {
            // Parse status line
            size_t space1 = line_str.find(' ');
            size_t space2 = line_str.find(' ', space1 + 1);
            if (space1 != std::string::npos && space2 != std::string::npos) {
                response.setStatusCode(std::stoi(line_str.substr(space1 + 1, space2 - space1 - 1)));
            }
        } else {
            // Parse header
            size_t colon = line_str.find(':');
            if (colon != std::string::npos) {
                std::string name = line_str.substr(0, colon);
                std::string value = line_str.substr(colon + 2); // Skip ": "
                response.addHeader(name, value);
            }
        }
    }

    // Read body
    std::stringstream buffer;
    char buf[4096];
    while (fgets(buf, sizeof(buf), file)) {
        buffer << buf;
    }
    response.setBody(buffer.str());
}

// ============================================================================
// Request Implementation
// ============================================================================

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

// ============================================================================
// Response Implementation
// ============================================================================

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

} // namespace acme
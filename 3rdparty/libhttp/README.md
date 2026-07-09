# HTTP Client Library

A C++ HTTP client library with GSSAPI/Kerberos authentication support for ACME protocol implementations.

## Features

- **HTTP Methods**: GET, POST, PUT, DELETE, HEAD, OPTIONS
- **Authentication**: GSSAPI/Kerberos support for SPNEGO authentication
- **Libraries**: Supports both libfetch and libcurl as underlying HTTP libraries
- **Headers**: Custom header management
- **Timeout**: Configurable request timeout
- **User Agent**: Customizable user agent string
- **Response Handling**: Status code, headers, body, and response time tracking

## Requirements

- C++26 compatible compiler
- GSSAPI development libraries (krb5-gssapi)
- Either libfetch or libcurl

## Installation

### Using CMake

```cmake
# Add the library to your project
add_subdirectory(3rdparty/libhttp)

# Link the library
target_link_libraries(your_target PRIVATE libhttp)
```

### Manual Installation

1. Include the headers:
```cpp
#include "3rdparty/libhttp/HTTPClient.hpp"
```

2. Link against the library and required dependencies:
```cmake
target_link_libraries(your_target PRIVATE libhttp)
```

## Usage

### Basic Usage

```cpp
#include "3rdparty/libhttp/HTTPClient.hpp"
#include <iostream>

using namespace acme;

int main() {
    // Create HTTP client
    HTTPClient client("http/acme.example.com", "/etc/krb5.keytab");
    
    // Initialize Kerberos authentication
    if (!client.initialize()) {
        std::cerr << "Failed to initialize client: " << client.getLastError() << std::endl;
        return 1;
    }
    
    // Make a GET request
    Response response;
    if (client.get("https://acme.example.com/directory", response)) {
        std::cout << "Status: " << response.getStatusCode() << std::endl;
        std::cout << "Response: " << response.getBody() << std::endl;
    } else {
        std::cerr << "Request failed: " << client.getLastError() << std::endl;
    }
    
    return 0;
}
```

### POST Request with JSON

```cpp
HTTPClient client;
client.initialize();

Response response;
std::string json_body = R"({
    "account": "https://acme.example.com/acme/acct/123",
    "nonce": "nonce123",
    "url": "https://acme.example.com/acme/new-authz"
})";

if (client.post("https://acme.example.com/acme/new-authz", json_body, response)) {
    std::cout << "Created: " << response.getBody() << std::endl;
}
```

### Custom Headers

```cpp
HTTPClient client;
client.initialize();

client.addHeader("Accept", "application/json");
client.addHeader("Content-Type", "application/json");
client.addHeader("User-Agent", "my-acme-client/1.0");

Response response;
client.get("https://acme.example.com/directory", response);
```

### Timeout Configuration

```cpp
HTTPClient client;
client.setTimeout(30);  // 30 seconds
client.initialize();

Response response;
client.get("https://acme.example.com/directory", response);
```

### Response Handling

```cpp
Response response;
client.get("https://acme.example.com/directory", response);

if (response.isSuccessful()) {
    std::cout << "Request successful!" << std::endl;
    std::cout << "Response time: " << response.getResponseTime() << "ms" << std::endl;
    std::cout << "Content-Type: " << response.getContentType() << std::endl;
    std::cout << "Body: " << response.getBody() << std::endl;
}

if (response.isRedirect()) {
    std::cout << "Redirect to: " << response.getEffectiveUrl() << std::endl;
}
```

## API Reference

### HTTPClient Class

#### Constructor
```cpp
HTTPClient(const std::string& principal, const std::string& keytab_path)
```
Creates an HTTP client with Kerberos authentication support.

#### Methods
- `bool initialize()` - Initialize Kerberos authentication
- `bool get(const std::string& url, Response& response)` - Make GET request
- `bool post(const std::string& url, const std::string& body, Response& response)` - Make POST request
- `bool put(const std::string& url, const std::string& body, Response& response)` - Make PUT request
- `bool del(const std::string& url, Response& response)` - Make DELETE request
- `void setHeaders(const std::map<std::string, std::string>& headers)` - Set custom headers
- `void addHeader(const std::string& name, const std::string& value)` - Add single header
- `void setTimeout(int timeout)` - Set request timeout
- `void setUserAgent(const std::string& userAgent)` - Set user agent
- `std::string getLastError() const` - Get last error message
- `bool isInitialized() const` - Check if client is initialized
- `std::string getPrincipal() const` - Get Kerberos principal
- `gss_ctx_id_t getContext() const` - Get GSSAPI context

### Request Class

#### Methods
- `void setBody(const std::string& body)` - Set request body
- `void setContentType(const std::string& contentType)` - Set Content-Type header
- `void setAccept(const std::string& accept)` - Set Accept header
- `void addHeader(const std::string& name, const std::string& value)` - Add custom header
- `std::string getMethodString() const` - Get HTTP method as string
- `std::string getUrl() const` - Get request URL
- `std::string getBody() const` - Get request body
- `const std::map<std::string, std::string>& getHeaders() const` - Get all headers
- `Method getMethod() const` - Get HTTP method enum
- `size_t getBodySize() const` - Get body size

### Response Class

#### Methods
- `int getStatusCode() const` - Get HTTP status code
- `const std::map<std::string, std::string>& getHeaders() const` - Get response headers
- `std::string getBody() const` - Get response body
- `std::string toString() const` - Get body as string
- `bool isSuccessful() const` - Check if status code is 2xx
- `bool isRedirect() const` - Check if status code is 3xx
- `std::string getContentType() const` - Get Content-Type header
- `size_t getContentLength() const` - Get Content-Length
- `std::string getLastError() const` - Get last error message
- `long getResponseTime() const` - Get response time in milliseconds
- `std::string getUrl() const` - Get requested URL
- `std::string getEffectiveUrl() const` - Get effective URL after redirects

## Building

### With libfetch

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### With libcurl

If libfetch is not available, the library will automatically use libcurl as a fallback.

## License

BSD-3-Clause

## Authors

ACME Protocol Implementation
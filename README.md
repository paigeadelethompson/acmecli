# ACME Protocol Implementation

A C++ implementation of the ACME (Automatic Certificate Management Environment) protocol for certificate management and issuance.

## Overview

The ACME protocol, defined in [RFC 8555](https://tools.ietf.org/html/rfc8555), is a protocol for automating certificate management tasks. This implementation provides both client and server components for:

- **Certificate Issuance**: Request and obtain TLS certificates from Certificate Authorities
- **Certificate Renewal**: Automatically renew expiring certificates
- **Certificate Revocation**: Request revocation of certificates
- **Account Management**: Create and manage ACME accounts
- **Challenge Validation**: Support for various challenge types (HTTP-01, DNS-01, TLS-ALPN-01)
- **Kerberos Authentication**: Secure authentication using GSS-API/Kerberos

## Features

### Client Features
- ACME protocol client implementation
- Support for multiple ACME directory endpoints
- Automatic certificate renewal
- Challenge validation for certificate issuance
- JSON-based request/response handling
- Kerberos authentication support
- Certificate storage and management

### Server Features
- ACME protocol server implementation
- Certificate generation and management
- Policy-based access control
- Challenge validation endpoints
- Account management
- Kerberos authentication for secure communication
- Support for multiple certificate authorities

### Security Features
- **Kerberos Authentication**: GSS-API based authentication for both client and server
- **Message Integrity**: Message Integrity Codes (MICs) for request verification
- **TLS Encryption**: Secure communication using OpenSSL
- **Certificate Management**: Automatic certificate lifecycle management
- **Replay Protection**: Timestamp-based replay attack prevention

## Architecture

```
acmecli/
├── include/                    # Public headers
│   ├── acme_client.hpp
│   ├── acme_server.hpp
│   ├── certificate_manager.hpp
│   └── policy_manager.hpp
├── src/
│   ├── client/                # Client implementation
│   │   ├── acme_client.cpp
│   │   └── main.cpp
│   └── server/                # Server implementation
│       ├── acme_server.cpp
│       ├── certificate_manager.cpp
│       ├── policy_manager.cpp
│       └── main.cpp
├── 3rdparty/
│   ├── jsoncpp/               # JSON library
│   ├── libconsole/            # Console utilities
│   └── libhttp/               # HTTP client/server with Kerberos
├── etc/                       # Configuration files
│   ├── acmed.conf             # Server configuration
│   └── policy.json            # Policy configuration
├── doc/                       # Documentation
│   ├── rfc6960.txt            # RFC 6960 (Certificate Transparency)
│   └── rfc8555.txt            # RFC 8555 (ACME Protocol)
└── build/                     # Build output
```

## Requirements

### Build Requirements
- C++26 compatible compiler (GCC 11+, Clang 13+, or MSVC 2022+)
- CMake 3.28 or higher
- OpenSSL development libraries
- GSSAPI development libraries (krb5-gssapi)
- JSON library (jsoncpp)

### Runtime Requirements
- OpenSSL runtime libraries
- GSSAPI runtime libraries (krb5)
- Kerberos keytab file (for Kerberos authentication)
- Valid ACME account credentials

## Installation

### Building from Source

```bash
# Clone the repository
git clone <repository-url>
cd acmecli

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake ..

# Build the project
cmake --build .

# Install (optional)
sudo make install
```

### Using CMake

```cmake
# Add the project to your build
add_subdirectory(path/to/acmecli)

# Link the libraries
target_link_libraries(your_target PRIVATE acme_client acme_server)
```

## Configuration

### Server Configuration

Edit `etc/acmed.conf`:

```ini
# Server configuration
server_port = 443
server_host = 0.0.0.0
certificate_path = /etc/ssl/certs/acme_server.crt
private_key_path = /etc/ssl/private/acme_server.key
ca_certificate_path = /etc/ssl/certs/ca-bundle.crt

# ACME configuration
acme_directory = https://acme-v02.api.letsencrypt.org/directory
account_key_path = /etc/acme/account.key
max_retries = 3
retry_delay = 30

# Kerberos configuration
kerberos_principal = HTTP/server.example.com@EXAMPLE.COM
keytab_path = /etc/krb5.keytab
```

### Policy Configuration

Edit `etc/policy.json`:

```json
{
  "max_cert_lifetime": 90,
  "min_cert_lifetime": 7,
  "allowed_challenges": ["http-01", "dns-01", "tls-alpn-01"],
  "rate_limits": {
    "requests_per_minute": 10,
    "certificates_per_account_per_day": 5
  },
  "certificate_transparency": true
}
```

### Kerberos Setup

1. **Create keytab file**:
```bash
kadmin.local -q "ktadd -norandkey -k /etc/krb5.keytab HTTP/server.example.com@EXAMPLE.COM"
```

2. **Configure Kerberos**:
```ini
# /etc/krb5.conf
[libdefaults]
    default_realm = EXAMPLE.COM
    default_tkt_enctypes = aes256-cts-hmac-sha1-96
    default_tgs_enctypes = aes256-cts-hmac-sha1-96

[realms]
    EXAMPLE.COM = {
        kdc = kdc.example.com
        admin_server = kdc.example.com
    }
```

## Usage

### Server Usage

```bash
# Start the ACME server
./build/acme_server -c etc/acmed.conf

# The server will:
# - Listen on configured port and host
# - Serve ACME protocol endpoints
# - Validate challenges
# - Manage certificates
# - Authenticate clients using Kerberos
```

### Client Usage

```bash
# Initialize client
./build/acme_client init --account-key /etc/acme/account.key

# Request a certificate
./build/acme_client request-cert \
  --domain example.com \
  --email admin@example.com \
  --challenge http-01

# Renew a certificate
./build/acme_client renew --certificate /etc/ssl/certs/example.com.crt

# Revoke a certificate
./build/acme_client revoke --certificate /etc/ssl/certs/example.com.crt
```

### Programmatic Usage

#### Client Example

```cpp
#include "acme_client.hpp"
#include <iostream>

using namespace acme;

int main() {
    // Create ACME client
    ACMEClient client("https://acme-v02.api.letsencrypt.org/directory");

    // Initialize with account key
    if (!client.initialize("/etc/acme/account.key")) {
        std::cerr << "Failed to initialize client" << std::endl;
        return 1;
    }

    // Request certificate
    CertificateRequest request;
    request.setDomain("example.com");
    request.setEmail("admin@example.com");
    request.setChallengeType(ChallengeType::HTTP_01);

    CertificateResponse response = client.requestCertificate(request);

    if (response.isSuccess()) {
        std::cout << "Certificate obtained: " << response.getCertificatePath() << std::endl;
    }

    return 0;
}
```

#### Server Example

```cpp
#include "acme_server.hpp"
#include <iostream>

using namespace acme;

int main() {
    // Create ACME server
    ACMEServer server;

    // Load configuration
    if (!server.loadConfig("etc/acmed.conf")) {
        std::cerr << "Failed to load configuration" << std::endl;
        return 1;
    }

    // Initialize Kerberos authentication
    if (!server.initializeKerberos("HTTP/server.example.com@EXAMPLE.COM",
                                   "/etc/krb5.keytab")) {
        std::cerr << "Failed to initialize Kerberos" << std::endl;
        return 1;
    }

    // Start server
    if (!server.start()) {
        std::cerr << "Failed to start server" << std::endl;
        return 1;
    }

    std::cout << "ACME server running on port " << server.getPort() << std::endl;

    return 0;
}
```

## ACME Protocol Support

This implementation supports the following ACME protocol features:

### Core Features
- [x] Account creation and management
- [x] Certificate requests (new-cert)
- [x] Certificate renewal (renewal)
- [x] Certificate revocation (revoke-cert)
- [x] Order creation and management
- [x] Authorization management
- [x] Challenge validation
- [x] Certificate status queries

### Challenge Types
- [x] HTTP-01 challenge
- [x] DNS-01 challenge
- [x] TLS-ALPN-01 challenge

### Certificate Management
- [x] Automatic certificate generation
- [x] Certificate storage and retrieval
- [x] Certificate renewal scheduling
- [x] Certificate revocation
- [x] Certificate transparency logging

### Security Features
- [x] JWS (JSON Web Signature) signing
- [x] Message Integrity Codes (MICs)
- [x] Replay protection
- [x] TLS encryption
- [x] Kerberos authentication

## Development

### Building with Debug Mode

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

### Building with Coverage

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="--coverage"
cmake --build build
cmake --build build --target test
```

### Running Tests

```bash
# Run all tests
./build/acme_client test

# Run specific test
./build/acme_client test --test-name certificate_manager_test
```

### Code Style

This project follows the following coding standards:
- C++26 standard
- Google C++ Style Guide
- CMake naming conventions
- Consistent header guards

## Documentation

- [RFC 8555: ACME Protocol](doc/rfc8555.txt)
- [RFC 6960: Certificate Transparency](doc/rfc6960.txt)
- [libhttp README](3rdparty/libhttp/README.md) - Kerberos authentication details

## Troubleshooting

### Common Issues

1. **Kerberos Authentication Failed**
   - Verify keytab file permissions (600)
   - Check Kerberos configuration
   - Ensure clock synchronization

2. **Certificate Request Failed**
   - Verify ACME directory URL
   - Check account key validity
   - Review challenge validation logs

3. **Build Errors**
   - Ensure all dependencies are installed
   - Check CMake version (3.28+)
   - Verify compiler supports C++26

### Debug Logging

Enable debug output by setting environment variables:

```bash
export ACME_DEBUG=1
export GSS_DEBUG=1
```

## License

BSD-3-Clause License

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new features
5. Submit a pull request

## Authors

ACME Protocol Implementation

## Acknowledgments

- [Let's Encrypt](https://letsencrypt.org/) - ACME protocol implementation reference
- [RFC 8555](https://tools.ietf.org/html/rfc8555) - ACME protocol specification
- [MIT Kerberos](https://web.mit.edu/kerberos/) - Kerberos implementation
- [OpenSSL](https://www.openssl.org/) - Cryptographic library

## References

- [RFC 8555: The ACME Protocol](https://tools.ietf.org/html/rfc8555)
- [RFC 6960: The X.509 Public Key Infrastructure Certificate and CRL Profile](https://tools.ietf.org/html/rfc6960)
- [RFC 4120: Kerberos V5](https://tools.ietf.org/html/rfc4120)
- [RFC 2743: Generic Security Service Application Program Interface](https://tools.ietf.org/html/rfc2743)
- [RFC 2744: Generic Security Service API: C Bindings](https://tools.ietf.org/html/rfc2744)
- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://tools.ietf.org/html/rfc8446)
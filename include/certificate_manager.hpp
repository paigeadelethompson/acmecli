#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace acme {

  class CertificateManager {
  public:
    CertificateManager(const std::string &ca_key_path,
                       const std::string &ca_cert_path,
                       const std::string &server_key_path,
                       const std::string &server_cert_path);

    bool initializeCA();
    bool generateCertificate(const std::string &common_name,
                             const std::string &csr_pem);
    std::string getCAKeyPath() const { return ca_key_path_; }
    std::string getCACertPath() const { return ca_cert_path_; }

  private:
    std::string ca_key_path_;
    std::string ca_cert_path_;
    std::string server_key_path_;
    std::string server_cert_path_;

    bool createSelfSignedCA();
    bool createServerCertificate();
    bool saveKey(const std::string &key_path, EVP_PKEY *key);
    bool saveCert(const std::string &cert_path, X509 *cert);
    EVP_PKEY *generateRSAKey(size_t key_size = 2048);
    X509 *generateX509(const std::string &common_name, EVP_PKEY *key,
                       bool is_ca = false);
    void addExtensions(X509 *cert, const std::string &common_name, bool is_ca);
  };

} // namespace acme
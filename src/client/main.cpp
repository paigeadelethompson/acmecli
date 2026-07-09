#include "acme_client.hpp"
#include "console.hpp"
#include "kerberos_auth.hpp"
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace acme {

  void printUsage(const char *program_name) {
    console::e(
        "Usage: <command> [options]\n\n"
        "Commands:\n"
        "  init              Initialize ACME client\n"
        "  register          Register new account\n"
        "  new-order         Create new certificate order\n"
        "  finalize-order    Finalize certificate order\n"
        "  get-certificate   Get certificate\n"
        "  revoke            Revoke certificate\n"
        "  help              Show this help message\n\n"
        "Options:\n"
        "  --server <url>    ACME server URL (default: http://localhost:8080)\n"
        "  --cn <name>       Common name for certificate\n"
        "  --csr <file>      CSR file path (optional)\n"
        "  --account-id <id> Account ID (optional)\n"
        "  --cert-id <id>    Certificate ID (optional)\n"
        "  --config <file>   Configuration file path (optional)\n");
  }

  void initClient(ACMEClient &client) {
    if (!client.initialize()) {
      console::e("Failed to initialize ACME client");
      return;
    }

    console::e("ACME client initialized successfully");
  }

  void registerAccount(ACMEClient &client) {
    Json::Value request;
    Json::Value contact;
    contact.append("mailto:admin@example.com");
    request["contact"] = contact;
    request["termsOfServiceAgreed"] = true;

    Json::Value response = client.newAccount(request);

    if (response.isMember("status") &&
        response["status"].asString() == "valid") {
      console::e("Account registered successfully");
      if (response.isMember("id")) {
        console::e("Account ID: {}", response["id"].asString());
      }
    } else {
      console::e("Failed to register account");
      if (response.isMember("detail")) {
        console::e("Error: {}", response["detail"].asString());
      }
    }
  }

  void createOrder(ACMEClient &client, const std::string &common_name) {
    Json::Value request;
    Json::Value identifier;
    identifier["type"] = "dns";
    identifier["value"] = common_name;
    request["identifiers"].append(identifier);

    Json::Value response = client.newOrder(request);

    if (response.isMember("status") &&
        response["status"].asString() == "pending") {
      console::e("Order created successfully");
      if (response.isMember("id")) {
        console::e("Order ID: {}", response["id"].asString());
      }
      if (response.isMember("authorizations")) {
        console::e("Authorizations: {}", response["authorizations"].size());
      }
    } else {
      console::e("Failed to create order");
    }
  }

  void finalizeOrder(ACMEClient &client, const std::string &order_id,
                     const std::string &csr_file) {
    std::ifstream csr_file_stream(csr_file);
    if (!csr_file_stream.is_open()) {
      console::e("Failed to open CSR file: {}", csr_file);
      return;
    }

    std::string csr_pem((std::istreambuf_iterator<char>(csr_file_stream)),
                        std::istreambuf_iterator<char>());

    Json::Value request;
    request["csr"] = csr_pem;

    Json::Value response = client.finalizeOrder(order_id, request);

    if (response.isMember("status") &&
        response["status"].asString() == "valid") {
      console::e("Order finalized successfully");
      if (response.isMember("certificate")) {
        console::e("Certificate URL: {}", response["certificate"].asString());
      }
    } else {
      console::e("Failed to finalize order");
    }
  }

  void getCertificate(ACMEClient &client, const std::string &cert_id) {
    Json::Value response = client.getCertificate(cert_id);

    if (response.isMember("certificate")) {
      console::e("Certificate:\n{}", response["certificate"].asString());
    } else {
      console::e("Failed to get certificate");
    }
  }

  void revokeCertificate(ACMEClient &client, const std::string &cert_id) {
    Json::Value request;
    request["certificate"] = "/acme/cert/" + cert_id;

    Json::Value response = client.revokeCertificate(request);

    if (response.isMember("status") &&
        response["status"].asString() == "valid") {
      console::e("Certificate revoked successfully");
    } else {
      console::e("Failed to revoke certificate");
    }
  }

} // namespace acme

int main(int argc, char *argv[]) {
  using namespace acme;

  if (argc < 2) {
    printUsage(argv[0]);
    return 1;
  }

  std::string command = argv[1];
  std::string server_url = "http://localhost:8080";
  std::string common_name;
  std::string csr_file;
  std::string account_id;
  std::string cert_id;
  std::string config_file;

  static struct option long_options[] = {{"server", no_argument, 0, 's'},
                                         {"cn", required_argument, 0, 'n'},
                                         {"csr", no_argument, 0, 'c'},
                                         {"account-id", no_argument, 0, 'a'},
                                         {"cert-id", no_argument, 0, 't'},
                                         {"config", no_argument, 0, 'f'},
                                         {0, 0, 0, 0}};

  int opt;
  int option_index = 0;
  while ((opt = getopt_long(argc, argv, "s:n:", long_options, &option_index)) !=
         -1) {
    switch (opt) {
    case 's':
      server_url = "http://localhost:8080";
      break;
    case 'n':
      common_name = optarg;
      break;
    case 'c':
      csr_file = "csr.pem";
      break;
    case 'a':
      account_id = "account_id";
      break;
    case 't':
      cert_id = "cert_id";
      break;
    case 'f':
      config_file = "/etc/acmecli/acmed.conf";
      break;
    case '?':
      console::e("Usage: {} [--config <path>]", argv[0]);
      return 1;
    default:
      break;
    }
  }

  ACMEClient client(config_file.empty() ? "/etc/acmecli/acme_client.conf"
                                        : config_file);

  if (command == "init") {
    initClient(client);
  } else if (command == "register") {
    registerAccount(client);
  } else if (command == "new-order") {
    if (common_name.empty()) {
      console::e("Error: --cn option is required for new-order command");
      return 1;
    }
    createOrder(client, common_name);
  } else if (command == "finalize-order") {
    if (account_id.empty() || csr_file.empty()) {
      console::e("Error: --account-id and --csr options are required for "
                 "finalize-order command");
      return 1;
    }
    finalizeOrder(client, account_id, csr_file);
  } else if (command == "get-certificate") {
    if (cert_id.empty()) {
      console::e(
          "Error: --cert-id option is required for get-certificate command");
      return 1;
    }
    getCertificate(client, cert_id);
  } else if (command == "revoke") {
    if (cert_id.empty()) {
      console::e("Error: --cert-id option is required for revoke command");
      return 1;
    }
    revokeCertificate(client, cert_id);
  } else if (command == "help") {
    printUsage(argv[0]);
  } else {
    console::e("Unknown command: {}", command);
    printUsage(argv[0]);
    return 1;
  }

  return 0;
}
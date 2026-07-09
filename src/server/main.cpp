#include "acme_server.hpp"
#include "console.hpp"
#include <iostream>
#include <csignal>
#include <memory>
#include <getopt.h>

namespace acme {

std::unique_ptr<ACMEServer> g_server;

void signalHandler(int signal) {
    console::e("\\nReceived signal {}, shutting down...", signal);
    if (g_server) {
        g_server->stop();
    }
    exit(0);
}

} // namespace acme

int main(int argc, char* argv[]) {
    using namespace acme;

    std::string config_path = "/etc/acmecli/acmed.conf";

    static struct option long_options[] = {
        {"config", required_argument, 0, 'c'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "c:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'c':
                config_path = optarg;
                break;
            case '?':
                console::e("Usage: {} [--config <path>]", argv[0]);
                return 1;
            default:
                break;
        }
    }

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    g_server = std::make_unique<ACMEServer>(config_path);

    if (!g_server->initialize()) {
        console::e("Failed to initialize ACME server");
        return 1;
    }

    g_server->run();

    return 0;
}
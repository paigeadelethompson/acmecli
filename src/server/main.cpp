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

#include "Console.hpp"
#include "acme_server.hpp"
#include <csignal>
#include <getopt.h>
#include <iostream>
#include <memory>

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

int main(int argc, char *argv[]) {
  using namespace acme;

  std::string config_path = "/etc/acmecli/acmed.conf";

  static struct option long_options[] = {{"config", required_argument, 0, 'c'},
                                         {0, 0, 0, 0}};

  int opt;
  int option_index = 0;
  while ((opt = getopt_long(argc, argv, "c:", long_options, &option_index)) !=
         -1) {
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
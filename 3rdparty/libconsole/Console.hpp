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

#include <format>
#include <iostream>
#include <mdspan>
#include <string_view>
#include <vector>

#ifdef _WIN32
#else
#include <sys/ioctl.h>
#include <unistd.h>
#endif

namespace console {

  // ANSI color codes
  namespace colors {
    constexpr const char *RESET = "\033[0m";
    constexpr const char *BOLD = "\033[1m";
    constexpr const char *DIM = "\033[2m";
    constexpr const char *ITALIC = "\033[3m";
    constexpr const char *UNDERLINE = "\033[4m";
    constexpr const char *BLINK = "\033[5m";
    constexpr const char *INVERT = "\033[7m";
    constexpr const char *HIDDEN = "\033[8m";

    // Foreground colors
    constexpr const char *BLACK = "\033[30m";
    constexpr const char *RED = "\033[31m";
    constexpr const char *GREEN = "\033[32m";
    constexpr const char *YELLOW = "\033[33m";
    constexpr const char *BLUE = "\033[34m";
    constexpr const char *MAGENTA = "\033[35m";
    constexpr const char *CYAN = "\033[36m";
    constexpr const char *WHITE = "\033[37m";

    // Background colors
    constexpr const char *BG_BLACK = "\033[40m";
    constexpr const char *BG_RED = "\033[41m";
    constexpr const char *BG_GREEN = "\033[42m";
    constexpr const char *BG_YELLOW = "\033[43m";
    constexpr const char *BG_BLUE = "\033[44m";
    constexpr const char *BG_MAGENTA = "\033[45m";
    constexpr const char *BG_CYAN = "\033[46m";
    constexpr const char *BG_WHITE = "\033[47m";
  } // namespace colors

  // Formatter presets
  namespace presets {
    constexpr const char *success = colors::GREEN;
    constexpr const char *error = colors::RED;
    constexpr const char *warning = colors::YELLOW;
    constexpr const char *info = colors::BLUE;
    constexpr const char *debug = colors::CYAN;
  } // namespace presets

  // Variadic output functions
  template <typename... Args>
  void i(std::format_string<Args...> fmt, Args &&...args) {
    std::cout << std::format(fmt, std::forward<Args>(args)...) << std::endl;
  }

  template <typename... Args>
  void e(std::format_string<Args...> fmt, Args &&...args) {
    std::cerr << std::format(fmt, std::forward<Args>(args)...) << std::endl;
  }

  // Print table with mdspan
  template <typename T>
  void printTable(const T &data, const std::vector<std::string> &headers) {
    // Implementation would go here
  }

  // Utility functions
  void clearScreen();
  void printBanner(const std::string &title);
  void printSeparator();

} // namespace console
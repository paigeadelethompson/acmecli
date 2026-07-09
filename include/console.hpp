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
  template <typename ElementType, typename Extents>
  void printTable(const std::mdspan<ElementType, Extents> &table) {
    if (table.extent(0) == 0 || table.extent(1) == 0) {
      return;
    }

    // Get terminal width using TIOCGWINSZ (default to 79 if not available)
    int termWidth = 79;

#ifdef TIOCGWINSZ
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
      termWidth = static_cast<int>(ws.ws_col);
    }
#endif

    // Table width is terminal width - 1, minimum 79
    int tableMaxWidth = std::max(79, termWidth - 1);

    // Calculate column widths based on content and available space
    std::vector<size_t> colWidths(table.extent(1), 0);

    // First pass: calculate minimum required width for each column
    for (size_t col = 0; col < table.extent(1); ++col) {
      size_t maxLen = 0;
      for (size_t row = 0; row < table.extent(0); ++row) {
        std::string val = static_cast<std::string>(table[row, col]);
        maxLen = std::max(maxLen, val.length());
      }
      colWidths[col] = maxLen + 2; // Add padding
    }

    // Calculate total width and adjust if needed
    size_t totalWidth = 0;
    for (size_t w : colWidths) {
      totalWidth += w;
    }

    // If table is wider than terminal, reduce column widths proportionally
    if (totalWidth > static_cast<size_t>(tableMaxWidth)) {
      double scale =
          static_cast<double>(tableMaxWidth - table.extent(1)) / totalWidth;
      for (size_t col = 0; col < table.extent(1); ++col) {
        colWidths[col] = std::max(static_cast<size_t>(2),
                                  static_cast<size_t>(colWidths[col] * scale));
      }
    }

    // Helper function to wrap text into lines of given width
    auto wrapText = [&](const std::string &text,
                        size_t width) -> std::vector<std::string> {
      std::vector<std::string> lines;
      if (width <= 1 || text.empty()) {
        lines.push_back(text);
        return lines;
      }

      size_t pos = 0;
      while (pos < text.length()) {
        size_t remaining = text.length() - pos;
        if (remaining <= width) {
          lines.push_back(text.substr(pos));
          break;
        }

        // Find last space within the width limit
        size_t endPos = pos + width;
        size_t lastSpace = text.find_last_of(' ', endPos - 1);

        if (lastSpace != std::string::npos && lastSpace >= pos) {
          lines.push_back(text.substr(pos, lastSpace - pos));
          pos = lastSpace + 1; // Skip the space
        } else {
          // No space found, break at width
          lines.push_back(text.substr(pos, width));
          pos += width;
        }
      }
      return lines;
    };

    // Helper to print a cell's wrapped content with proper alignment
    auto printCell = [&](const std::string &text, size_t width) {
      auto lines = wrapText(text, width);
      for (size_t i = 0; i < lines.size(); ++i) {
        if (i == 0) {
          std::cout << std::format("{:<{}}", lines[i], width);
        } else {
          // Continuation line - just print with same width
          std::cout << std::format("{:<{}}", lines[i], width);
        }
      }
    };

    // Print header row (may span multiple lines)
    size_t maxHeaderLines = 0;
    std::vector<std::vector<std::string>> headerLines(table.extent(1));
    for (size_t col = 0; col < table.extent(1); ++col) {
      headerLines[col] =
          wrapText(static_cast<std::string>(table[0, col]), colWidths[col]);
      maxHeaderLines = std::max(maxHeaderLines, headerLines[col].size());
    }

    for (size_t lineIdx = 0; lineIdx < maxHeaderLines; ++lineIdx) {
      for (size_t col = 0; col < table.extent(1); ++col) {
        if (col > 0)
          std::cout << "|";
        if (lineIdx < headerLines[col].size()) {
          std::cout << std::format("{:<{}}", headerLines[col][lineIdx],
                                   colWidths[col]);
        } else {
          std::cout << std::string(colWidths[col], ' ');
        }
      }
      std::cout << std::endl;
    }

    // Print separator line
    for (size_t col = 0; col < table.extent(1); ++col) {
      if (col > 0)
        std::cout << "|";
      std::string sep(colWidths[col], '-');
      std::cout << std::format("{:<{}}", sep, colWidths[col]);
    }
    std::cout << std::endl;

    // Print data rows (each may span multiple lines)
    for (size_t row = 1; row < table.extent(0); ++row) {
      size_t maxRowLines = 0;
      std::vector<std::vector<std::string>> rowLines(table.extent(1));

      // First pass: calculate max lines needed for this row
      for (size_t col = 0; col < table.extent(1); ++col) {
        rowLines[col] =
            wrapText(static_cast<std::string>(table[row, col]), colWidths[col]);
        maxRowLines = std::max(maxRowLines, rowLines[col].size());
      }

      // Print each line of the row
      for (size_t lineIdx = 0; lineIdx < maxRowLines; ++lineIdx) {
        for (size_t col = 0; col < table.extent(1); ++col) {
          if (col > 0)
            std::cout << "|";
          if (lineIdx < rowLines[col].size()) {
            std::cout << std::format("{:<{}}", rowLines[col][lineIdx],
                                     colWidths[col]);
          } else {
            std::cout << std::string(colWidths[col], ' ');
          }
        }
        std::cout << std::endl;
      }
    }
  }

  // Print LDIF document with mdspan
  template <typename ElementType, typename Extents>
  void printLdif(const std::mdspan<ElementType, Extents> &ldif) {
    for (size_t row = 0; row < ldif.extent(0); ++row) {
      for (size_t col = 0; col < ldif.extent(1); ++col) {
        std::cout << std::format("{} ", ldif[row, col]);
      }
      std::cout << std::endl;
    }
  }

} // namespace console
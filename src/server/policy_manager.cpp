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

#include "policy_manager.hpp"
#include "Console.hpp"
#include <algorithm>
#include <fstream>
#include <sstream>

namespace acme {

  PolicyManager::PolicyManager(const std::string &policy_file_path)
      : policy_file_path_(policy_file_path) {}

  bool PolicyManager::loadPolicy() {
    std::ifstream policy_file(policy_file_path_);
    if (!policy_file.is_open()) {
      console::e("Warning: Policy file not found, creating empty policy");
      policy_file.close();

      // Create empty policy file
      Json::Value policy;
      policy["principals"] = Json::Value();

      std::ofstream new_policy_file(policy_file_path_);
      new_policy_file << policy;
      new_policy_file.close();

      return true;
    }

    Json::Value policy;
    policy_file >> policy;

    return parsePolicy(policy);
  }

  bool PolicyManager::parsePolicy(const Json::Value &policy) {
    policy_.clear();

    if (!policy.isMember("principals")) {
      return true;
    }

    const Json::Value &principals = policy["principals"];
    for (const auto &principal_entry : principals) {
      std::string principal = principal_entry["principal"].asString();
      Json::Value cns = principal_entry["cns"];

      for (const auto &cn : cns) {
        policy_[principal].push_back(cn.asString());
      }
    }

    return true;
  }

  bool PolicyManager::validate(const std::string &principal,
                               const std::string &cn) {
    auto it = policy_.find(principal);
    if (it == policy_.end()) {
      return false;
    }

    const auto &cns = it->second;
    for (const auto &allowed_cn : cns) {
      if (allowed_cn == cn) {
        return true;
      }
    }

    return false;
  }

  void PolicyManager::addPrincipal(const std::string &principal,
                                   const std::string &cn) {
    policy_[principal].push_back(cn);
    updatePolicyFile();
  }

  void PolicyManager::removePrincipal(const std::string &principal) {
    policy_.erase(principal);
    updatePolicyFile();
  }

  void PolicyManager::updatePolicyFile() {
    Json::Value policy;
    policy["principals"] = Json::Value();

    for (const auto &entry : policy_) {
      Json::Value principal_entry;
      principal_entry["principal"] = entry.first;

      Json::Value cns;
      for (const auto &cn : entry.second) {
        cns.append(cn);
      }
      principal_entry["cns"] = cns;

      policy["principals"].append(principal_entry);
    }

    std::ofstream policy_file(policy_file_path_);
    policy_file << policy;
    policy_file.close();
  }

} // namespace acme
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
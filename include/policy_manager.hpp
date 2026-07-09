#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>

#include "json/json.h"

namespace acme {

class PolicyManager {
public:
    PolicyManager(const std::string& policy_file_path);

    bool loadPolicy();
    bool validate(const std::string& principal, const std::string& cn);
    void addPrincipal(const std::string& principal, const std::string& cn);
    void removePrincipal(const std::string& principal);
    void updatePolicyFile();

private:
    std::string policy_file_path_;
    std::unordered_map<std::string, std::vector<std::string>> policy_;

    bool parsePolicy(const Json::Value& policy);
};

} // namespace acme
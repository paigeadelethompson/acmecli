#pragma once

#include <memory>
#include <string>

#include <gssapi/gssapi.h>

namespace acme {

  class KerberosAuth {
  public:
    KerberosAuth(const std::string &principal, const std::string &keytab_path);

    bool initialize();
    bool authenticateClient(const std::string &token, std::string &principal);
    bool validateToken(const std::string &token);

    // GSSAPI token operations
    OM_uint32 wrapToken(gss_ctx_id_t context, const std::string &token,
                        std::string &wrapped_token);
    OM_uint32 unwrapToken(gss_ctx_id_t context,
                          const std::string &wrapped_token, std::string &token);

    // Client-side signing operations using GSS_GetMIC for JWS signing
    OM_uint32 signMessage(const std::string &message, std::string &signature);
    OM_uint32 verifyMessage(const std::string &message, const std::string &signature);

  private:
    std::string principal_;
    std::string keytab_path_;
    gss_cred_id_t server_cred_;
    gss_cred_id_t client_cred_;
    gss_ctx_id_t context_;

    OM_uint32 acquireCredentials();
    OM_uint32 acquireClientCredentials();
    void cleanup();
    OM_uint32 verifyToken(gss_ctx_id_t context, const std::string &token,
                          std::string &principal);
    void cleanupGSS(gss_ctx_id_t context, gss_cred_id_t cred);
  };

} // namespace acme
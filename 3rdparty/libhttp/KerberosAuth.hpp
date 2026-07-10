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

    // Message integrity operations using GSS-API for both server and client
    OM_uint32 signMessage(const std::string &message, std::string &signature);
    OM_uint32 verifyMessage(const std::string &message,
                            const std::string &signature);

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
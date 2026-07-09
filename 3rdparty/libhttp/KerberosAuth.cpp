#include "KerberosAuth.hpp"
#include "Console.hpp"
#include <fstream>
#include <iostream>
#include <sstream>

namespace acme {

  KerberosAuth::KerberosAuth(const std::string &principal,
                             const std::string &keytab_path)
      : principal_(principal), keytab_path_(keytab_path),
        server_cred_(GSS_C_NO_CREDENTIAL) {}

  bool KerberosAuth::initialize() {
    if (acquireCredentials() != GSS_S_COMPLETE) {
      console::e("Failed to acquire Kerberos credentials");
      return false;
    }

    console::e("Kerberos authentication initialized for principal: {}",
               principal_);
    return true;
  }

  bool KerberosAuth::authenticateClient(const std::string &token,
                                        std::string &principal) {
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;

    OM_uint32 maj_stat = verifyToken(context, token, principal);

    if (maj_stat != GSS_S_COMPLETE) {
      cleanupGSS(context, GSS_C_NO_CREDENTIAL);
      return false;
    }

    cleanupGSS(context, GSS_C_NO_CREDENTIAL);
    return true;
  }

  bool KerberosAuth::validateToken(const std::string &token) {
    std::string principal;
    return authenticateClient(token, principal);
  }

  OM_uint32 KerberosAuth::acquireCredentials() {
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc name_buf;
    gss_name_t name = GSS_C_NO_NAME;

    name_buf.length = principal_.length();
    name_buf.value = const_cast<char *>(principal_.c_str());

    maj_stat = gss_import_name(&min_stat, &name_buf, GSS_C_NT_HOSTBASED_SERVICE,
                               &name);
    if (maj_stat != GSS_S_COMPLETE) {
      return maj_stat;
    }

    maj_stat =
        gss_acquire_cred(&min_stat, name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                         GSS_C_ACCEPT, &server_cred_, nullptr, nullptr);

    gss_release_name(&min_stat, &name);

    return maj_stat;
  }

  void KerberosAuth::cleanup() {
    if (server_cred_ != GSS_C_NO_CREDENTIAL) {
      OM_uint32 maj_stat, min_stat;
      gss_release_cred(&min_stat, &server_cred_);
      server_cred_ = GSS_C_NO_CREDENTIAL;
    }
  }

  OM_uint32 KerberosAuth::verifyToken(gss_ctx_id_t context,
                                      const std::string &token,
                                      std::string &principal) {
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc input_token;
    gss_buffer_desc output_token;
    gss_name_t client_name = GSS_C_NO_NAME;

    input_token.length = token.length();
    input_token.value = const_cast<char *>(token.c_str());

    OM_uint32 ret_flags = 0;
    OM_uint32 time_rec = 0;
    gss_cred_id_t delegated_cred = GSS_C_NO_CREDENTIAL;
    gss_OID mech_type = GSS_C_NO_OID;
    maj_stat = gss_accept_sec_context(&min_stat, &context, server_cred_,
                                      &input_token, GSS_C_NO_CHANNEL_BINDINGS,
                                      &client_name, &mech_type, &output_token,
                                      &ret_flags, &time_rec, &delegated_cred);

    if (maj_stat == GSS_S_COMPLETE) {
      gss_buffer_desc name_buf;
      gss_display_name(&min_stat, client_name, &name_buf, nullptr);
      principal =
          std::string(static_cast<char *>(name_buf.value), name_buf.length);
      gss_release_buffer(&min_stat, &name_buf);
    }

    gss_release_name(&min_stat, &client_name);

    return maj_stat;
  }

  OM_uint32 KerberosAuth::wrapToken(gss_ctx_id_t context,
                                    const std::string &token,
                                    std::string &wrapped_token) {
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc input_token;
    gss_buffer_desc output_token;

    input_token.length = token.length();
    input_token.value = const_cast<char *>(token.c_str());

    maj_stat = gss_wrap(&min_stat, context, true, GSS_C_QOP_DEFAULT,
                        &input_token, nullptr, &output_token);

    if (maj_stat == GSS_S_COMPLETE) {
      wrapped_token = std::string(static_cast<char *>(output_token.value),
                                  output_token.length);
      gss_release_buffer(&min_stat, &output_token);
    }

    return maj_stat;
  }

  OM_uint32 KerberosAuth::unwrapToken(gss_ctx_id_t context,
                                      const std::string &wrapped_token,
                                      std::string &token) {
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc input_token;
    gss_buffer_desc output_token;

    input_token.length = wrapped_token.length();
    input_token.value = const_cast<char *>(wrapped_token.c_str());

    maj_stat = gss_unwrap(&min_stat, context, &input_token, &output_token,
                          nullptr, nullptr);

    if (maj_stat == GSS_S_COMPLETE) {
      token = std::string(static_cast<char *>(output_token.value),
                          output_token.length);
      gss_release_buffer(&min_stat, &output_token);
    }

    return maj_stat;
  }

  // ============================================================================
  // GSS_GetMIC - Message Integrity Code for JWS signing
  // ============================================================================

  OM_uint32 KerberosAuth::signMessage(const std::string &message,
                                      std::string &signature) {
    if (client_cred_ == GSS_C_NO_CREDENTIAL) {
      console::e("No client credentials available for signing");
      return GSS_S_NO_CRED;
    }

    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc input_token;
    gss_buffer_desc output_token;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;

    input_token.length = message.length();
    input_token.value = const_cast<char *>(message.c_str());

    // Initialize security context for MIC generation
    maj_stat = gss_init_sec_context(
        &min_stat, client_cred_, &context, GSS_C_NO_NAME, GSS_C_NO_OID,
        GSS_C_MUTUAL_FLAG, GSS_C_INDEFINITE, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr);

    if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
      console::e("Failed to initialize GSS context for MIC generation");
      return maj_stat;
    }

    // Generate MIC using GSS_GetMIC
    maj_stat = gss_get_mic(&min_stat, context, GSS_C_QOP_DEFAULT, &input_token,
                           &output_token);

    if (maj_stat == GSS_S_COMPLETE) {
      signature = std::string(static_cast<char *>(output_token.value),
                              output_token.length);
      gss_release_buffer(&min_stat, &output_token);
      console::i("Message MIC generated successfully, length: {}",
                 signature.length());
    } else {
      console::e("Failed to generate MIC with GSS_GetMIC");
    }

    // Clean up the context
    if (context != GSS_C_NO_CONTEXT) {
      gss_delete_sec_context(&min_stat, &context, GSS_C_NO_BUFFER);
    }

    return maj_stat;
  }

  OM_uint32 KerberosAuth::verifyMessage(const std::string &message,
                                        const std::string &signature) {
    if (server_cred_ == GSS_C_NO_CREDENTIAL) {
      console::e("No server credentials available for verification");
      return GSS_S_NO_CRED;
    }

    // For verification, we need to use GSS_VerifyMIC
    // This requires a GSS context to be established first
    if (context_ == GSS_C_NO_CONTEXT) {
      console::e("No GSS context available for verification");
      return GSS_S_NO_CONTEXT;
    }

    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc input_token;
    gss_buffer_desc output_token;

    input_token.length = message.length();
    input_token.value = const_cast<char *>(message.c_str());

    maj_stat = gss_verify_mic(&min_stat, context_, &input_token, &output_token,
                              nullptr);

    if (maj_stat == GSS_S_COMPLETE) {
      console::i("Message verified successfully");
      gss_release_buffer(&min_stat, &output_token);
    } else {
      console::e("Failed to verify message");
    }

    return maj_stat;
  }

  void KerberosAuth::cleanupGSS(gss_ctx_id_t context, gss_cred_id_t cred) {
    OM_uint32 maj_stat, min_stat;

    if (context != GSS_C_NO_CONTEXT) {
      gss_delete_sec_context(&min_stat, &context, GSS_C_NO_BUFFER);
    }

    if (cred != GSS_C_NO_CREDENTIAL) {
      gss_release_cred(&min_stat, &cred);
    }
  }

} // namespace acme
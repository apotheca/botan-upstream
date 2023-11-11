/*
* (C) 2015,2017,2018 Jack Lloyd
* (C) 2023 Leo Dillinger
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/pubkey.h>

#include <botan/internal/ffi_pkey.h>
#include <botan/internal/ffi_rng.h>
#include <botan/internal/ffi_util.h>

#include <memory>

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/data_src.h>
   #include <botan/x509_ca.h>
   #include <botan/x509_crl.h>
   #include <botan/x509self.h>
   #include <botan/x509cert.h>
   #include <botan/x509path.h>
   #include <botan/pkix_types.h>
   #include <botan/certstor.h>
   // #include <botan/certstor_flatfile.h>
#endif

extern "C" {

using namespace Botan_FFI;

/*
* X.509 distinguished names
**************************/

BOTAN_FFI_DECLARE_STRUCT(botan_x509_dn_struct, Botan::X509_DN, 0x85a46206);

int botan_x509_dn_create(botan_x509_dn_t* dn) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_dn_create_from_multimap(
   botan_x509_dn_t* dn,
   const uint8_t* keys[], const size_t key_lens[],
   const uint8_t* vals[], const size_t val_lens[],
   size_t count
   ) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_dn_to_string(
   uint8_t out[], size_t* out_len,
   botan_x509_dn_t dn) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_dn_has_field(
   botan_x509_dn_t dn,
   const uint8_t key[], size_t key_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_dn_get_first_attribute(
   uint8_t out[], size_t* out_len,
   botan_x509_dn_t dn,
   const uint8_t key[], size_t key_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_dn_get_attribute(
   uint8_t** vals, size_t* val_sizes, size_t* val_count,
   botan_x509_dn_t dn,
   const uint8_t key[], size_t key_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_dn_contents(
   uint8_t** keys, size_t* key_sizes, uint8_t** vals, size_t* val_sizes, size_t* count,
   botan_x509_dn_t dn) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_dn_add_attribute(
   botan_x509_dn_t dn,
   const uint8_t key[], size_t key_len,
   const uint8_t val[], size_t val_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/*
* X.509 Certificate Extensions
**************************/

#if defined(BOTAN_HAS_X509_CERTIFICATES)

BOTAN_FFI_DECLARE_STRUCT(botan_x509_cert_ext_struct, Botan::Certificate_Extension, 0xb5ffd19c);
BOTAN_FFI_DECLARE_STRUCT(botan_x509_exts_struct, Botan::Extensions, 0xac898f09);

#endif


int botan_x509_cert_ext_destroy(botan_x509_cert_ext_t ext) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(ext);
#else
   BOTAN_UNUSED(ca);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_exts_destroy(botan_x509_exts_t exts) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(exts);
#else
   BOTAN_UNUSED(ca);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/*
* X.509 certificate
**************************/

#if defined(BOTAN_HAS_X509_CERTIFICATES)

BOTAN_FFI_DECLARE_STRUCT(botan_x509_cert_struct, Botan::X509_Certificate, 0x8F628937);

#endif

int botan_x509_cert_load_file(botan_x509_cert_t* cert_obj, const char* cert_path) {
   if(!cert_obj || !cert_path) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto c = std::make_unique<Botan::X509_Certificate>(cert_path);
      *cert_obj = new botan_x509_cert_struct(std::move(c));
      return BOTAN_FFI_SUCCESS;
   });

#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_dup(botan_x509_cert_t* cert_obj, botan_x509_cert_t cert) {
   if(!cert_obj) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto c = std::make_unique<Botan::X509_Certificate>(safe_get(cert));
      *cert_obj = new botan_x509_cert_struct(std::move(c));
      return BOTAN_FFI_SUCCESS;
   });

#else
   BOTAN_UNUSED(cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_load(botan_x509_cert_t* cert_obj, const uint8_t cert_bits[], size_t cert_bits_len) {
   if(!cert_obj || !cert_bits) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DataSource_Memory bits(cert_bits, cert_bits_len);
      auto c = std::make_unique<Botan::X509_Certificate>(bits);
      *cert_obj = new botan_x509_cert_struct(std::move(c));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(cert_bits_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_public_key(botan_x509_cert_t cert, botan_pubkey_t* key) {
   if(key == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   *key = nullptr;

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto public_key = safe_get(cert).subject_public_key();
      *key = new botan_pubkey_struct(std::move(public_key));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_issuer_dn(
   botan_x509_cert_t cert, const char* key, size_t index, uint8_t out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert,
                          [=](const auto& c) { return write_str_output(out, out_len, c.issuer_info(key).at(index)); });
#else
   BOTAN_UNUSED(cert, key, index, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_issuer_dn(
   botan_x509_dn_t* dn,
   botan_x509_cert_t cert,
   const char* key,
   size_t index) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_subject_dn(
   botan_x509_cert_t cert, const char* key, size_t index, uint8_t out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert,
                          [=](const auto& c) { return write_str_output(out, out_len, c.subject_info(key).at(index)); });
#else
   BOTAN_UNUSED(cert, key, index, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_subject_dn(
   botan_x509_dn_t* dn,
   botan_x509_cert_t cert,
   const char* key,
   size_t index) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_to_string(botan_x509_cert_t cert, char out[], size_t* out_len) {
   return copy_view_str(reinterpret_cast<uint8_t*>(out), out_len, botan_x509_cert_view_as_string, cert);
}

int botan_x509_cert_view_as_string(botan_x509_cert_t cert, botan_view_ctx ctx, botan_view_str_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return invoke_view_callback(view, ctx, c.to_string()); });
#else
   BOTAN_UNUSED(cert, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_allowed_usage(botan_x509_cert_t cert, unsigned int key_usage) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) -> int {
      const Botan::Key_Constraints k = static_cast<Botan::Key_Constraints>(key_usage);
      if(c.allowed_usage(k))
         return BOTAN_FFI_SUCCESS;
      return 1;
   });
#else
   BOTAN_UNUSED(cert, key_usage);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_destroy(botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(cert);
#else
   BOTAN_UNUSED(cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_time_starts(botan_x509_cert_t cert, char out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert,
                          [=](const auto& c) { return write_str_output(out, out_len, c.not_before().to_string()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_time_expires(botan_x509_cert_t cert, char out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert,
                          [=](const auto& c) { return write_str_output(out, out_len, c.not_after().to_string()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_not_before(botan_x509_cert_t cert, uint64_t* time_since_epoch) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { *time_since_epoch = c.not_before().time_since_epoch(); });
#else
   BOTAN_UNUSED(cert, time_since_epoch);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_not_after(botan_x509_cert_t cert, uint64_t* time_since_epoch) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { *time_since_epoch = c.not_after().time_since_epoch(); });
#else
   BOTAN_UNUSED(cert, time_since_epoch);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_serial_number(botan_x509_cert_t cert, uint8_t out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return write_vec_output(out, out_len, c.serial_number()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_fingerprint(botan_x509_cert_t cert, const char* hash, uint8_t out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return write_str_output(out, out_len, c.fingerprint(hash)); });
#else
   BOTAN_UNUSED(cert, hash, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_authority_key_id(botan_x509_cert_t cert, uint8_t out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return write_vec_output(out, out_len, c.authority_key_id()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_subject_key_id(botan_x509_cert_t cert, uint8_t out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return write_vec_output(out, out_len, c.subject_key_id()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_public_key_bits(botan_x509_cert_t cert, uint8_t out[], size_t* out_len) {
   return copy_view_bin(out, out_len, botan_x509_cert_view_public_key_bits, cert);
}

int botan_x509_cert_view_public_key_bits(botan_x509_cert_t cert, botan_view_ctx ctx, botan_view_bin_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert,
                          [=](const auto& c) { return invoke_view_callback(view, ctx, c.subject_public_key_bits()); });
#else
   BOTAN_UNUSED(cert, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_hostname_match(botan_x509_cert_t cert, const char* hostname) {
   if(hostname == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return c.matches_dns_name(hostname) ? 0 : -1; });
#else
   BOTAN_UNUSED(cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_verify(int* result_code,
                           botan_x509_cert_t cert,
                           const botan_x509_cert_t* intermediates,
                           size_t intermediates_len,
                           const botan_x509_cert_t* trusted,
                           size_t trusted_len,
                           const char* trusted_path,
                           size_t required_strength,
                           const char* hostname_cstr,
                           uint64_t reference_time) {
   if(required_strength == 0) {
      required_strength = 110;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const std::string hostname((hostname_cstr == nullptr) ? "" : hostname_cstr);
      const Botan::Usage_Type usage = Botan::Usage_Type::UNSPECIFIED;
      const auto validation_time = reference_time == 0
                                      ? std::chrono::system_clock::now()
                                      : std::chrono::system_clock::from_time_t(static_cast<time_t>(reference_time));

      std::vector<Botan::X509_Certificate> end_certs;
      end_certs.push_back(safe_get(cert));
      for(size_t i = 0; i != intermediates_len; ++i) {
         end_certs.push_back(safe_get(intermediates[i]));
      }

      std::unique_ptr<Botan::Certificate_Store> trusted_from_path;
      std::unique_ptr<Botan::Certificate_Store_In_Memory> trusted_extra;
      std::vector<Botan::Certificate_Store*> trusted_roots;

      if(trusted_path && *trusted_path) {
         trusted_from_path = std::make_unique<Botan::Certificate_Store_In_Memory>(trusted_path);
         trusted_roots.push_back(trusted_from_path.get());
      }

      if(trusted_len > 0) {
         trusted_extra = std::make_unique<Botan::Certificate_Store_In_Memory>();
         for(size_t i = 0; i != trusted_len; ++i) {
            trusted_extra->add_certificate(safe_get(trusted[i]));
         }
         trusted_roots.push_back(trusted_extra.get());
      }

      Botan::Path_Validation_Restrictions restrictions(false, required_strength);

      auto validation_result =
         Botan::x509_path_validate(end_certs, restrictions, trusted_roots, hostname, usage, validation_time);

      if(result_code) {
         *result_code = static_cast<int>(validation_result.result());
      }

      if(validation_result.successful_validation()) {
         return 0;
      } else {
         return 1;
      }
   });
#else
   BOTAN_UNUSED(result_code, cert, intermediates, intermediates_len, trusted);
   BOTAN_UNUSED(trusted_len, trusted_path, hostname_cstr, reference_time);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

const char* botan_x509_cert_validation_status(int code) {
   if(code < 0) {
      return nullptr;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   Botan::Certificate_Status_Code sc = static_cast<Botan::Certificate_Status_Code>(code);
   return Botan::to_string(sc);
#else
   return nullptr;
#endif
}

/*
* X.509 certificate revocation list
**************************/

#if defined(BOTAN_HAS_X509_CERTIFICATES)

BOTAN_FFI_DECLARE_STRUCT(botan_x509_crl_struct, Botan::X509_CRL, 0x2C628910);
// Found in x509_crl.h
BOTAN_FFI_DECLARE_STRUCT(botan_x509_crl_entry_struct, Botan::CRL_Entry, 0x4dcfbd84);

#endif

int botan_x509_crl_load_file(botan_x509_crl_t* crl_obj, const char* crl_path) {
   if(!crl_obj || !crl_path) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto c = std::make_unique<Botan::X509_CRL>(crl_path);
      *crl_obj = new botan_x509_crl_struct(std::move(c));
      return BOTAN_FFI_SUCCESS;
   });

#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_load(botan_x509_crl_t* crl_obj, const uint8_t crl_bits[], size_t crl_bits_len) {
   if(!crl_obj || !crl_bits) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DataSource_Memory bits(crl_bits, crl_bits_len);
      auto c = std::make_unique<Botan::X509_CRL>(bits);
      *crl_obj = new botan_x509_crl_struct(std::move(c));
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(crl_bits_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_destroy(botan_x509_crl_t crl) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(crl);
#else
   BOTAN_UNUSED(crl);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_is_revoked(botan_x509_crl_t crl, botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(crl, [=](const auto& c) { return c.is_revoked(safe_get(cert)) ? 0 : -1; });
#else
   BOTAN_UNUSED(cert);
   BOTAN_UNUSED(crl);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_verify_with_crl(int* result_code,
                                    botan_x509_cert_t cert,
                                    const botan_x509_cert_t* intermediates,
                                    size_t intermediates_len,
                                    const botan_x509_cert_t* trusted,
                                    size_t trusted_len,
                                    const botan_x509_crl_t* crls,
                                    size_t crls_len,
                                    const char* trusted_path,
                                    size_t required_strength,
                                    const char* hostname_cstr,
                                    uint64_t reference_time) {
   if(required_strength == 0) {
      required_strength = 110;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const std::string hostname((hostname_cstr == nullptr) ? "" : hostname_cstr);
      const Botan::Usage_Type usage = Botan::Usage_Type::UNSPECIFIED;
      const auto validation_time = reference_time == 0
                                      ? std::chrono::system_clock::now()
                                      : std::chrono::system_clock::from_time_t(static_cast<time_t>(reference_time));

      std::vector<Botan::X509_Certificate> end_certs;
      end_certs.push_back(safe_get(cert));
      for(size_t i = 0; i != intermediates_len; ++i) {
         end_certs.push_back(safe_get(intermediates[i]));
      }

      std::unique_ptr<Botan::Certificate_Store> trusted_from_path;
      std::unique_ptr<Botan::Certificate_Store_In_Memory> trusted_extra;
      std::unique_ptr<Botan::Certificate_Store_In_Memory> trusted_crls;
      std::vector<Botan::Certificate_Store*> trusted_roots;

      if(trusted_path && *trusted_path) {
         trusted_from_path = std::make_unique<Botan::Certificate_Store_In_Memory>(trusted_path);
         trusted_roots.push_back(trusted_from_path.get());
      }

      if(trusted_len > 0) {
         trusted_extra = std::make_unique<Botan::Certificate_Store_In_Memory>();
         for(size_t i = 0; i != trusted_len; ++i) {
            trusted_extra->add_certificate(safe_get(trusted[i]));
         }
         trusted_roots.push_back(trusted_extra.get());
      }

      if(crls_len > 0) {
         trusted_crls = std::make_unique<Botan::Certificate_Store_In_Memory>();
         for(size_t i = 0; i != crls_len; ++i) {
            trusted_crls->add_crl(safe_get(crls[i]));
         }
         trusted_roots.push_back(trusted_crls.get());
      }

      Botan::Path_Validation_Restrictions restrictions(false, required_strength);

      auto validation_result =
         Botan::x509_path_validate(end_certs, restrictions, trusted_roots, hostname, usage, validation_time);

      if(result_code) {
         *result_code = static_cast<int>(validation_result.result());
      }

      if(validation_result.successful_validation()) {
         return 0;
      } else {
         return 1;
      }
   });
#else
   BOTAN_UNUSED(result_code, cert, intermediates, intermediates_len, trusted);
   BOTAN_UNUSED(trusted_len, trusted_path, hostname_cstr, reference_time, crls, crls_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_entry_destroy(botan_x509_crl_entry_t entry) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(entry);
#else
   BOTAN_UNUSED(crl);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/*
* X.509 certificate authority
**************************/

// TODO: Implement functions mentioned in the handbook, vs implement every function?

#if defined(BOTAN_HAS_X509_CERTIFICATES)

BOTAN_FFI_DECLARE_STRUCT(botan_x509_ca_struct, Botan::X509_CA, 0x63458bb4);
BOTAN_FFI_DECLARE_STRUCT(botan_x509_csr_struct, Botan::PKCS10_Request, 0x3a369b4b);

#endif

int botan_x509_ca_destroy(botan_x509_ca_t ca) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(ca);
#else
   BOTAN_UNUSED(ca);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_csr_destroy(botan_x509_csr_t csr) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(csr);
#else
   BOTAN_UNUSED(csr);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ca_create(
   botan_x509_ca_t* ca,
   botan_x509_cert_t cert,
   botan_privkey_t key,
   const char* hash_fn,
   botan_rng_t rng) {

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   // NOTE: I'm not even sure why I have botan_x509_ca_create instead
   // of just using botan_x509_ca_create_padding. I'm just following
   // the handbook.
   return botan_x509_ca_create_padding(ca, cert, key, hash_fn, "", rng);
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ca_create_padding(
   botan_x509_ca_t* ca,
   botan_x509_cert_t cert,
   botan_privkey_t key,
   const char* hash_fn,
   const char* padding_fn,
   botan_rng_t rng) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

   *ca = nullptr;

   if(hash_fn == nullptr || padding_fn == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   // TODO: Should I do this? Or use BOTAN_FFI_VISIT (which implies this too)?
   // I think ffi_guard_thunk is used when creating something, and then
   // BOTAN_FFI_VISIT is used on the function's primary object we are calling
   return ffi_guard_thunk(__func__, [=]() -> int {

      std::unique_ptr<Botan::X509_CA> ca_obj;

      auto cert_obj = safe_get(cert);
      Botan::Private_Key& key_obj = safe_get(key);
      // NOTE: These are probably unnecessary now with the null ptr check
      // std::string hash_fn_str = hash_fn ? hash_fn : "";
      // std::string padding_fn_str = padding_fn ? padding_fn : "";
      Botan::RandomNumberGenerator& rng_obj = safe_get(rng);

      *ca_obj = Botan::X509_CA(cert_obj, key_obj, hash_fn, padding_fn, rng_obj);

      if(ca_obj) {
         *ca = new botan_x509_ca_struct(std::move(ca_obj));
         return BOTAN_FFI_SUCCESS;
      }

      return BOTAN_FFI_ERROR_UNKNOWN_ERROR;

   });

#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ca_sign_request(
   botan_x509_cert_t* cert,
   botan_x509_ca_t ca,
   botan_x509_csr_t csr,
   botan_rng_t rng,
   uint64_t not_before,
   uint64_t not_after) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ca_make_cert_serial(
   botan_x509_cert_t* cert,
   botan_pk_op_sign_t signer,
   botan_rng_t rng,
   botan_mp_t serial_number,
   const char* sig_algo,
   botan_pubkey_t key,
   uint64_t not_before,
   uint64_t not_after,
   const uint8_t issuer_dn[], size_t issuer_dn_len,
   const uint8_t subject_dn[], size_t subject_dn_len,
   botan_x509_exts_t exts) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ca_choose_extensions(
   botan_x509_exts_t* exts,
   botan_x509_csr_t csr,
   botan_x509_cert_t ca_cert,
   const char* hash_fn) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/*
* X.509 certificate signing request
**************************/

#if defined(BOTAN_HAS_X509_CERTIFICATES)

BOTAN_FFI_DECLARE_STRUCT(botan_x509_cert_options_struct, Botan::X509_Cert_Options, 0x90c5a192);

#endif

int botan_x509_create_cert_req(
   botan_x509_csr_t* csr,
   botan_x509_cert_options_t opts,
   botan_privkey_t key,
   const char* hash_fn,
   botan_rng_t rng) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_csr_create(
   botan_x509_csr_t* csr,
   botan_privkey_t key,
   const uint8_t subject_dn[], size_t subject_dn_len,
   botan_x509_exts_t extensions,
   const char* hash_fn,
   botan_rng_t rng,
   const char* padding_fn,
   const char* challenge) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_create_self_signed_cert(
   botan_x509_cert_t* cert,
   botan_x509_cert_options_t opts,
   botan_privkey_t key,
   const char* hash_fn,
   botan_rng_t rng) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/*
* X.509 Certificate Store
**************************/

/**
* Certificate Store Interface
*/

BOTAN_FFI_DECLARE_STRUCT(botan_x509_cert_store_struct, Botan::Certificate_Store, 0x114215c5);

int botan_x509_cert_store_destroy(botan_x509_cert_store_t* cert_store) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

// NOTE: "Returns" a null pointer if not found?
int botan_x509_cert_store_find_cert(
   botan_x509_cert_t* cert,
   botan_x509_cert_store_t cert_store,
   const uint8_t subject_dn[], size_t subject_dn_len,
   const uint8_t key_id[], size_t key_id_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_store_find_all_certs(
   // botan_x509_cert_t* certs, size_t* certs_len,
   // or
   botan_x509_cert_t** certs, size_t* certs_len,
   botan_x509_cert_store_t cert_store,
   const uint8_t subject_dn[], size_t subject_dn_len,
   const uint8_t key_id[], size_t key_id_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

// NOTE: "Returns" a null pointer if not found?
int botan_x509_cert_store_find_cert_by_pubkey_sha1(
   botan_x509_cert_t* cert,
   botan_x509_cert_store_t cert_store,
   // NOTE: SHA1 hash length is static, so we can just drop the size_t
   const uint8_t key_hash[]) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

// NOTE: "Returns" a null pointer if not found?
int botan_x509_cert_store_find_cert_by_raw_subject_dn_sha256(
   botan_x509_cert_t* cert,
   botan_x509_cert_store_t cert_store,
   // NOTE: SHA1 hash length is static, so we can just drop the size_t
   const uint8_t subject_hash[]) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

// NOTE: "Returns" a null pointer if not found?
int botan_x509_cert_store_find_crl_for(
   botan_x509_crl_t* crl,
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

// NOTE: Returns cert_store.certificate_known ? 0 : -1;
int botan_x509_cert_store_certificate_known(
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/**
* In Memory Certificate Store
*/
int botan_x509_cert_store_in_memory_load_dir(
   botan_x509_cert_store_t* cert_store,
   const char* dir_path) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_store_in_memory_load_cert(
   botan_x509_cert_store_t* cert_store,
   botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_store_in_memory_create(
   botan_x509_cert_store_t* cert_store) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_store_in_memory_add_certificate(
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_store_in_memory_add_crl(
   botan_x509_cert_store_t cert_store,
   botan_x509_crl_t crl) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   // TODO: BOTAN_UNUSED(...)
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

} // extern "C"

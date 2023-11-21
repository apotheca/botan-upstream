/*
* (C) 2015,2017,2018 Jack Lloyd
* (C) 2023 Leo Dillinger
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/pubkey.h>
// #include <botan/sqlite3.h>

#include <botan/internal/ffi_pkey.h>
#include <botan/internal/ffi_rng.h>
#include <botan/internal/ffi_util.h>

#include <map>
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
   #include <botan/certstor_flatfile.h>
   #include <botan/certstor_sql.h>
   // #include <botan/certstor_sqlite.h>
   #include <botan/certstor_system.h>
   // #include <botan/certstor_macos.h>
   // #include <botan/certstor_windows.h>
#endif

extern "C" {

using namespace Botan_FFI;

/*
* X.509 general
**************************/

// NOTE: std::string constructors should be performing copy on
// our const char*, so transfer of ownership inwards should be safe

// NOTE: I believe that since write_str_output allocates an extra final byte
// per 'str.size() + 1' there are many cases (distinguished names etc) in which
// I should be using write_vec_output instead, as the distinguished names et al
// may contain null bytes

#if defined(BOTAN_HAS_X509_CERTIFICATES)

// TODO: Should probably be NAME,TYPE,FIELD,...
#define BOTAN_FFI_IMPL_FIELD_SETTER(NAME,FIELD,TYPE,SETFIELD)  \
   int botan_ ## NAME ## _set_ ## FIELD(                       \
      botan_ ## NAME ## _t NAME ## _obj,                       \
      TYPE FIELD                                               \
   ) {                                                         \
      return BOTAN_FFI_VISIT(NAME ## _obj, [=](auto& obj) {    \
         SETFIELD                                              \
      });                                                      \
   }

#else

// TODO: Should probably be NAME,TYPE,FIELD,...
#define BOTAN_FFI_IMPL_FIELD_SETTER(NAME,FIELD,TYPE,SETFIELD)  \
   int botan_ ## NAME ## _set_ ## FIELD(                       \
      botan_ ## NAME ## _t NAME ## _obj,                       \
      TYPE FIELD                                               \
   ) {                                                         \
      BOTAN_UNUSED(NAME ## _obj, FIELD);                       \
      return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;                  \                                                \
   }

#endif

#define BOTAN_FFI_IMPL_FIELD_SETTER_CSTRING(NAME,FIELD)     \
   BOTAN_FFI_IMPL_FIELD_SETTER(NAME,FIELD, const char*, {   \
      obj.FIELD = FIELD ? FIELD : "";                       \
      return BOTAN_FFI_SUCCESS;                             \
   })

/*
* X.509 distinguished names
**************************/

BOTAN_FFI_DECLARE_STRUCT(botan_x509_dn_struct, Botan::X509_DN, 0x85a46206);

int botan_x509_dn_destroy(botan_x509_dn_t dn) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(dn);
#else
   BOTAN_UNUSED(dn);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_dn_create(botan_x509_dn_t* dn) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

   if (dn == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto dn_ptr = std::make_unique<Botan::X509_DN>();
      *dn = new botan_x509_dn_struct(std::move(dn_ptr));
      return BOTAN_FFI_SUCCESS;
   });

#else
   BOTAN_UNUSED(dn);
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
   BOTAN_UNUSED(dn,keys,key_lens,vals,val_lens,count);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(dn,keys,key_lens,vals,val_lens,count);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_dn_to_string(
   uint8_t out[], size_t* out_len,
   botan_x509_dn_t dn) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(dn, [=](const Botan::X509_DN& obj) {
      return write_str_output(out, out_len, obj.to_string() );
   });
#else
   BOTAN_UNUSED(out,out_len,dn);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_dn_has_field(
   botan_x509_dn_t dn,
   const uint8_t key[], size_t key_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(dn, [=](const Botan::X509_DN& obj) {
      if (obj.has_field(std::string(Botan::cast_uint8_ptr_to_char(key),key_len))) {
         return 0;
      } else {
         return 1;
      }
   });
#else
   BOTAN_UNUSED(dn,key,key_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

// TODO: What to do when attribute is not found?
// Raise a specific error code? Return empty string?
int botan_x509_dn_get_first_attribute(
   uint8_t out[], size_t* out_len,
   botan_x509_dn_t dn,
   const uint8_t key[], size_t key_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(dn, [=](const Botan::X509_DN& obj) {
      auto result = obj.get_first_attribute(std::string(Botan::cast_uint8_ptr_to_char(key),key_len));
      return write_str_output(out, out_len, result);
   });
#else
   BOTAN_UNUSED(out,out_len,dn,key,key_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_dn_get_attribute(
   uint8_t** vals, size_t* val_sizes, size_t* val_count,
   botan_x509_dn_t dn,
   const uint8_t key[], size_t key_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(dn, [=](const Botan::X509_DN& obj) {

      if (val_count == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      auto attribute = obj.get_attribute(std::string(Botan::cast_uint8_ptr_to_char(key),key_len));
      size_t required_count = attribute.size();
      size_t allocated_count = *val_count;
      *val_count = required_count;

      if (allocated_count < required_count) {
         return BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE;
      }

      if (val_sizes == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      // NOTE: This ensures that the sizes are populated even if a single item fails
      int result = BOTAN_FFI_SUCCESS;
      for (size_t i = 0; i < required_count; i++) {
         if (result == BOTAN_FFI_SUCCESS) {
            result = write_str_output(*(vals + i), val_sizes + i, attribute[i]);
         } else {
            val_sizes[i] = attribute[i].size();
         }
      }
      return static_cast<BOTAN_FFI_ERROR>(result);
      
   });
#else
   BOTAN_UNUSED(vals,val_sizes,val_count,dn,key,key_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_dn_contents(
   uint8_t** keys, size_t* key_sizes, uint8_t** vals, size_t* val_sizes, size_t* count,
   botan_x509_dn_t dn) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(dn, [=](const Botan::X509_DN& obj) {

      if (count == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      auto contents = obj.contents();

      size_t required_count = contents.size();
      size_t allocated_count = *count;
      *count = required_count;

      if (allocated_count < required_count) {
         return BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE;
      }

      if (key_sizes == nullptr || val_sizes == nullptr) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      // NOTE: This ensures that the sizes are populated even if a single item fails
      int result = BOTAN_FFI_SUCCESS;
      int i = 0;
      for (auto it = contents.begin(); it != contents.end(); ++it,++i) {
         if (result == BOTAN_FFI_SUCCESS) {
            result = write_str_output(*(keys + i), key_sizes + i, it->first);
            if (result == BOTAN_FFI_SUCCESS) {
               result = write_str_output(*(vals + i), val_sizes + i, it->second);
            } else {
               val_sizes[i] = it->second.size();
            }
         } else {
            key_sizes[i] = it->first.size();
            val_sizes[i] = it->second.size();
         }
      }
      return static_cast<BOTAN_FFI_ERROR>(result);
      
   });
#else
   BOTAN_UNUSED(keys,key_sizes,vals,val_sizes,count,dn);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_dn_add_attribute(
   botan_x509_dn_t dn,
   const uint8_t key[], size_t key_len,
   const uint8_t val[], size_t val_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(dn, [=](Botan::X509_DN& obj) {

      // TODO: Determine whether this is th proper idiom (here and elsewhere with DNs)
      auto k = std::string(Botan::cast_uint8_ptr_to_char(key),key_len);
      auto v = std::string(Botan::cast_uint8_ptr_to_char(val),val_len);

      obj.add_attribute(k,v);

      return BOTAN_FFI_SUCCESS;

   });
#else
   BOTAN_UNUSED(dn,key,key_len,val,val_len);
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
   BOTAN_UNUSED(ext);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_exts_destroy(botan_x509_exts_t exts) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(exts);
#else
   BOTAN_UNUSED(exts);
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
   BOTAN_UNUSED(dn,cert,key,index);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(dn,cert,key,index);
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
   BOTAN_UNUSED(dn,cert,key,index);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(dn,cert,key,index);
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

// TODO: More CRL functions

int botan_x509_crl_entry_destroy(botan_x509_crl_entry_t entry) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(entry);
#else
   BOTAN_UNUSED(entry);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_entry_create(
   botan_x509_crl_entry_t* entry,
   botan_x509_cert_t cert,
   uint32_t reason_code) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

   if(entry == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto entry_ptr = std::make_unique<Botan::CRL_Entry>(
         safe_get(cert),
         static_cast<Botan::CRL_Code>(reason_code)
      );
      *entry = new botan_x509_crl_entry_struct(std::move(entry_ptr));
      return BOTAN_FFI_SUCCESS;
   });

#else
   BOTAN_UNUSED(entry,cert,reason_code);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_entry_get_serial_number(
   uint8_t out[], size_t* out_len,
   botan_x509_crl_entry_t entry) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   BOTAN_UNUSED(out,out_len,entry);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(out,out_len,entry);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_entry_get_expire_time(
   uint64_t* expire_time,
   botan_x509_crl_entry_t entry) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   BOTAN_UNUSED(expire_time,entry);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(expire_time,entry);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_entry_get_reason_code(
   uint32_t* reason_code,
   botan_x509_crl_entry_t entry) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   BOTAN_UNUSED(reason_code,entry);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(reason_code,entry);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_entry_get_extensions(
   botan_x509_exts_t* exts,
   botan_x509_crl_entry_t entry) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   BOTAN_UNUSED(exts,entry);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(exts,entry);
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
   BOTAN_UNUSED(ca,cert,key,hash_fn,rng);
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
   BOTAN_UNUSED(ca,cert,key,hash_fn,padding_fn,rng);
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
   BOTAN_UNUSED(cert,ca,csr,rng,not_before,not_after);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(cert,ca,csr,rng,not_before,not_after);
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
   BOTAN_UNUSED(cert,signer,rng,serial_number,sig_algo,key,not_before,not_after);
   BOTAN_UNUSED(issuer_dn,issuer_dn_len,subject_dn,subject_dn_len,exts);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(cert,signer,rng,serial_number,sig_algo,key,not_before,not_after);
   BOTAN_UNUSED(issuer_dn,issuer_dn_len,subject_dn,subject_dn_len,exts);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ca_choose_extensions(
   botan_x509_exts_t* exts,
   botan_x509_csr_t csr,
   botan_x509_cert_t ca_cert,
   const char* hash_fn) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   BOTAN_UNUSED(exts,csr,ca_cert,hash_fn);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(exts,csr,ca_cert,hash_fn);
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

   if(csr == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      // Is this the right way to deal with this?
      // It *compiles* but I hesitate to conclude
      // that this is correct
      std::unique_ptr<Botan::PKCS10_Request> csr_ptr; 
      *csr_ptr = Botan::X509::create_cert_req(
         safe_get(opts),
         safe_get(key),
         hash_fn ? hash_fn : "",
         safe_get(rng)
      );
      *csr = new botan_x509_csr_struct(std::move(csr_ptr));
      return BOTAN_FFI_SUCCESS;
   });

#else
   BOTAN_UNUSED(csr,opts,key,hash_fn,rng);
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

   // if(csr == nullptr || subject_dn == nullptr) {
   //    return BOTAN_FFI_ERROR_NULL_POINTER;
   // }

   // return ffi_guard_thunk(__func__, [=]() -> int {
   //    // TODO: ...
   //    return BOTAN_FFI_SUCCESS;
   // });

   BOTAN_UNUSED(csr,key,subject_dn,subject_dn_len,extensions,hash_fn,rng,padding_fn,challenge);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(csr,key,subject_dn,subject_dn_len,extensions,hash_fn,rng,padding_fn,challenge);
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

   if(cert == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      // Is this the right way to deal with this?
      // It *compiles* but I hesitate to conclude
      // that this is correct
      std::unique_ptr<Botan::X509_Certificate> cert_ptr; 
      *cert_ptr = Botan::X509::create_self_signed_cert(
         safe_get(opts),
         safe_get(key),
         hash_fn ? hash_fn : "",
         safe_get(rng)
      );
      *cert = new botan_x509_cert_struct(std::move(cert_ptr));
      return BOTAN_FFI_SUCCESS;
   });

#else
   BOTAN_UNUSED(cert,opts,key,hash_fn,rng);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/*
* X.509 Certificate Options
**************************/

int botan_x509_cert_options_destroy(botan_x509_cert_options_t opts) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(opts);
#else
   BOTAN_UNUSED(opts);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_options_create(
   botan_x509_cert_options_t* opts) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

   if(opts == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto opts_obj = std::make_unique<Botan::X509_Cert_Options>();
      *opts = new botan_x509_cert_options_struct(std::move(opts_obj));
      return BOTAN_FFI_SUCCESS;
   });
   
#else
   BOTAN_UNUSED(opts);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_options_create_common(
   botan_x509_cert_options_t* opts,
   const char* common_name,
   const char* country,
   const char* organization,
   const char* org_unit,
   uint32_t expiration_time) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

   if(opts == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto opts_obj = std::make_unique<Botan::X509_Cert_Options>();

      // TODO: Ensure copy / casting to string / transfer of ownership
      // NOTE: May be able to replace with:
      // opts_obj->field =  field ? std::string(field) : "";
      // or even with autocasting (need to verify, I don't like to assume):
      // opts_obj->field =  field ? field : "";
      if (common_name != nullptr) {
         opts_obj->common_name =  std::string(common_name);
      }
      if (country != nullptr) {
         opts_obj->country =  std::string(country);
      }
      if (organization != nullptr) {
         opts_obj->organization =  std::string(organization);
      }
      if (org_unit != nullptr) {
         opts_obj->org_unit =  std::string(org_unit);
      }

      // TODO: Set expiration time
      // if (expiration_time != 0) {
      //    opts_obj->start = now;
      //    opts_obj->end = now + expiration_time;
      // }
      BOTAN_UNUSED(expiration_time);

      *opts = new botan_x509_cert_options_struct(std::move(opts_obj));
      return BOTAN_FFI_SUCCESS;
   });

#else
   BOTAN_UNUSED(opts,common_name,country,organization,org_unit);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

BOTAN_FFI_IMPL_FIELD_SETTER_CSTRING(x509_cert_options,common_name);
BOTAN_FFI_IMPL_FIELD_SETTER_CSTRING(x509_cert_options,country);
BOTAN_FFI_IMPL_FIELD_SETTER_CSTRING(x509_cert_options,organization);
BOTAN_FFI_IMPL_FIELD_SETTER_CSTRING(x509_cert_options,org_unit);

// TODO: Replaced copied setters with define for array
int botan_x509_cert_options_set_more_org_units(
   botan_x509_cert_options_t opts,
   const char** more_org_units, size_t more_org_units_len
) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(opts, [=](Botan::X509_Cert_Options& opts_obj) {
      opts_obj.more_org_units = std::vector<std::string>(
         more_org_units,
         more_org_units + more_org_units_len
      );
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(opts,more_org_units,more_org_units_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

BOTAN_FFI_IMPL_FIELD_SETTER_CSTRING(x509_cert_options,locality);
BOTAN_FFI_IMPL_FIELD_SETTER_CSTRING(x509_cert_options,state);
BOTAN_FFI_IMPL_FIELD_SETTER_CSTRING(x509_cert_options,serial_number);
BOTAN_FFI_IMPL_FIELD_SETTER_CSTRING(x509_cert_options,email);
BOTAN_FFI_IMPL_FIELD_SETTER_CSTRING(x509_cert_options,uri);
BOTAN_FFI_IMPL_FIELD_SETTER_CSTRING(x509_cert_options,ip);
BOTAN_FFI_IMPL_FIELD_SETTER_CSTRING(x509_cert_options,dns);

int botan_x509_cert_options_set_more_dns(
   botan_x509_cert_options_t opts,
   const char** more_dns, size_t more_dns_len
) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(opts, [=](Botan::X509_Cert_Options& opts_obj) {
      opts_obj.more_dns = std::vector<std::string>(
         more_dns,
         more_dns + more_dns_len
      );
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(opts,more_dns,more_dns_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

BOTAN_FFI_IMPL_FIELD_SETTER_CSTRING(x509_cert_options,xmpp);
BOTAN_FFI_IMPL_FIELD_SETTER_CSTRING(x509_cert_options,challenge);

BOTAN_FFI_IMPL_FIELD_SETTER(x509_cert_options,start,uint64_t,{
   auto seconds = std::chrono::seconds(start);
   auto duration = std::chrono::duration_cast<std::chrono::system_clock::time_point::duration>(seconds);
   auto tp = std::chrono::system_clock::time_point(duration);
   obj.start = Botan::X509_Time(tp);
   return BOTAN_FFI_SUCCESS;
});

BOTAN_FFI_IMPL_FIELD_SETTER(x509_cert_options,end,uint64_t,{
   auto seconds = std::chrono::seconds(end);
   auto duration = std::chrono::duration_cast<std::chrono::system_clock::time_point::duration>(seconds);
   auto tp = std::chrono::system_clock::time_point(duration);
   obj.end = Botan::X509_Time(tp);
   return BOTAN_FFI_SUCCESS;
});

// TODO: Convenience functions for set_start_duration, set_expires

BOTAN_FFI_IMPL_FIELD_SETTER(x509_cert_options,is_ca,bool,{
   obj.is_CA = is_ca;
   return BOTAN_FFI_SUCCESS;
});

BOTAN_FFI_IMPL_FIELD_SETTER(x509_cert_options,path_limit,size_t,{
   obj.path_limit = path_limit;
   return BOTAN_FFI_SUCCESS;
});

// NOTE: May validly be a string and not need be changed to uint8_t** + size_t
BOTAN_FFI_IMPL_FIELD_SETTER_CSTRING(x509_cert_options,padding_scheme);

// Or _set_key_usage
// NOTE: key constraints use unsigned int in ffi, definitely need to give it something proper
BOTAN_FFI_IMPL_FIELD_SETTER(x509_cert_options,key_constraints,unsigned int,{
   obj.constraints = static_cast<Botan::Key_Constraints>(key_constraints);
   return BOTAN_FFI_SUCCESS;
});

// NOTE: Technically should take OIDs but no data type for that
// TODO: Create list / spreadsheet of FFI data type mappings
int botan_x509_cert_options_set_ex_constraints(
   botan_x509_cert_options_t opts,
   const char** ex_constraints, size_t ex_constraints_len
) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(opts, [=](Botan::X509_Cert_Options& opts_obj) {
      // TODO: Probably throw a BAD_PARAMETER on failing OID parse
      std::vector<Botan::OID> oids;
      std::transform(
         ex_constraints,
         ex_constraints + ex_constraints_len,
         oids.begin(),
         [](const char* ex_constraint) {
            return Botan::OID::from_string(std::string(ex_constraint));
         }
      );
      opts_obj.ex_constraints = oids;
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(opts,ex_constraints,ex_constraints_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

BOTAN_FFI_IMPL_FIELD_SETTER(x509_cert_options,extensions,botan_x509_exts_t,{
   obj.extensions = safe_get(extensions);
   return BOTAN_FFI_SUCCESS;
});

/*
* X.509 Certificate Store
**************************/

/**
* Certificate Store Interface
*/

BOTAN_FFI_DECLARE_STRUCT(botan_x509_cert_store_struct, Botan::Certificate_Store, 0x114215c5);

int botan_x509_cert_store_destroy(botan_x509_cert_store_t cert_store) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(cert_store);
#else
   BOTAN_UNUSED(cert_store);
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
   BOTAN_UNUSED(cert,cert_store,subject_dn,subject_dn_len,key_id,key_id_len);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(cert,cert_store,subject_dn,subject_dn_len,key_id,key_id_len);
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
   BOTAN_UNUSED(certs,certs_len,cert_store,subject_dn,subject_dn_len,key_id,key_id_len);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(certs,certs_len,cert_store,subject_dn,subject_dn_len,key_id,key_id_len);
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
   BOTAN_UNUSED(cert,cert_store,key_hash);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(cert,cert_store,key_hash);
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
   BOTAN_UNUSED(cert,cert_store,subject_hash);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(cert,cert_store,subject_hash);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

// NOTE: "Returns" a null pointer if not found?
int botan_x509_cert_store_find_crl_for(
   botan_x509_crl_t* crl,
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   BOTAN_UNUSED(crl,cert_store,cert);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(crl,cert_store,cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

// NOTE: Returns cert_store.certificate_known ? 0 : -1;
int botan_x509_cert_store_certificate_known(
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   BOTAN_UNUSED(cert_store,cert);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(cert_store,cert);
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

   if(cert_store == nullptr || dir_path == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto cert_store_obj = std::make_unique<Botan::Certificate_Store_In_Memory>(std::string(dir_path));
      *cert_store = new botan_x509_cert_store_struct(std::move(cert_store_obj));
      return BOTAN_FFI_SUCCESS;
   });

#else
   BOTAN_UNUSED(cert_store,dir_path);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_store_in_memory_load_cert(
   botan_x509_cert_store_t* cert_store,
   botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

   if(cert_store == nullptr || cert == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto cert_store_obj = std::make_unique<Botan::Certificate_Store_In_Memory>(safe_get(cert));
      *cert_store = new botan_x509_cert_store_struct(std::move(cert_store_obj));
      return BOTAN_FFI_SUCCESS;
   });

#else
   BOTAN_UNUSED(cert_store,cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_store_in_memory_create(
   botan_x509_cert_store_t* cert_store) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

   if(cert_store == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto cert_store_obj = std::make_unique<Botan::Certificate_Store_In_Memory>();
      *cert_store = new botan_x509_cert_store_struct(std::move(cert_store_obj));
      return BOTAN_FFI_SUCCESS;
   });

#else
   BOTAN_UNUSED(cert_store);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_store_in_memory_add_certificate(
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert_store, [=](auto& obj) {
      if (auto store = dynamic_cast<Botan::Certificate_Store_In_Memory*>(&obj)) {
         store->add_certificate(safe_get(cert));
         return BOTAN_FFI_SUCCESS;
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });
#else
   BOTAN_UNUSED(cert_store,cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_store_in_memory_add_crl(
   botan_x509_cert_store_t cert_store,
   botan_x509_crl_t crl) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert_store, [=](auto& obj) {
      if (auto store = dynamic_cast<Botan::Certificate_Store_In_Memory*>(&obj)) {
         store->add_crl(safe_get(crl));
         return BOTAN_FFI_SUCCESS;
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });
#else
   BOTAN_UNUSED(cert_store,crl);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/**
* Flatfile Certificate Store
* Certificate Store that is backed by a file of PEMs of trusted CAs.
*/

int botan_x509_cert_store_flatfile_create(
   botan_x509_cert_store_t* cert_store,
   const char* file_path,
   bool ignore_non_ca) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

   if(cert_store == nullptr || file_path == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto cert_store_obj = std::make_unique<Botan::Flatfile_Certificate_Store>(
         std::string(file_path),
         ignore_non_ca);
      *cert_store = new botan_x509_cert_store_struct(std::move(cert_store_obj));
      return BOTAN_FFI_SUCCESS;
   });

#else
   BOTAN_UNUSED(cert_store,file_path,ignore_non_ca);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/**
* SQL Certificate Store
* Certificate and private key store backed by an SQL database.
*/

// NOTE: Returns boolean success code
int botan_x509_cert_store_sql_insert_cert(
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

   return BOTAN_FFI_VISIT(cert_store, [=](auto& obj) {
      if (auto store = dynamic_cast<Botan::Certificate_Store_In_SQL*>(&obj)) {
         if(store->insert_cert(safe_get(cert))) {
            return BOTAN_FFI_SUCCESS;
         } else {
            return BOTAN_FFI_INVALID_VERIFIER;
         }
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });

#else
   BOTAN_UNUSED(cert_store,cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

// NOTE: Returns boolean success code
int botan_x509_cert_store_sql_remove_cert(
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

   return BOTAN_FFI_VISIT(cert_store, [=](auto& obj) {
      if (auto store = dynamic_cast<Botan::Certificate_Store_In_SQL*>(&obj)) {
         if(store->remove_cert(safe_get(cert))) {
            return BOTAN_FFI_SUCCESS;
         } else {
            return BOTAN_FFI_INVALID_VERIFIER;
         }
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });

#else
   BOTAN_UNUSED(cert_store,cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

// NOTE: Returns nullPtr if not found
int botan_x509_cert_store_sql_find_key(
   botan_privkey_t* key,
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

   if(key == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(cert_store, [=](auto& obj) {
      if (auto store = dynamic_cast<Botan::Certificate_Store_In_SQL*>(&obj)) {

         // NOTE: This returns a shared_ptr, and the following obviously
         // doesn't work. because botan_privkey_struct expects a unique_ptr:
         // auto key_obj = std::make_unique<Botan::Private_Key>(key_obj);
         // *key = new botan_privkey_struct(std::move(key_obj));
         // return BOTAN_FFI_SUCCESS;
         // Since we can't do that, I'm not sure what I ought to do
         // Certificate used to use shared_ptr, but it looks like
         // stores / databases got missed?
         // NOTE: Can't load an arbitrary private key?
         // NOTE: might be able to use the unique_ptr<type>() constructor
         // instead of make_unique, to capture resulting objects that aren't
         // vended by constructor
         return BOTAN_FFI_ERROR_INTERNAL_ERROR;

      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });

   BOTAN_UNUSED(key,cert_store,cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

// NOTE: NOT FINISHED - NEED TO RETURN AN ARRAY OF CERTIFICATES
// NOTE: Do we need a double-pointer - see how botan_x509_cert_verify_with_crl
// handles it - but also that's taking an array as INPUT, not OUTPUT
int botan_x509_cert_store_sql_find_certs_for_key(
   botan_x509_cert_t** certs, size_t* certs_len,
   botan_x509_cert_store_t cert_store,
   botan_privkey_t key) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

   if(certs == nullptr || certs_len == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(cert_store, [=](auto& obj) {
      if (auto store = dynamic_cast<Botan::Certificate_Store_In_SQL*>(&obj)) {
         auto result = store->find_certs_for_key(safe_get(key));
         // TODO: vector<X509_Certificate> to botan_x509_cert_t* certs, size_t certs_len
         // *certs = ...
         // *certs_len = result.size;
         // return BOTAN_FFI_SUCCESS;
         return BOTAN_FFI_ERROR_INTERNAL_ERROR;
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });

#else
   BOTAN_UNUSED(certs,certs_len,cert_store,key);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

// NOTE: Returns boolean success code
int botan_x509_cert_store_sql_insert_key(
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert,
   botan_privkey_t key) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

   return BOTAN_FFI_VISIT(cert_store, [=](auto& obj) {
      if (auto store = dynamic_cast<Botan::Certificate_Store_In_SQL*>(&obj)) {
         if(store->insert_key(safe_get(cert),safe_get(key))) {
            return BOTAN_FFI_SUCCESS;
         } else {
            return BOTAN_FFI_INVALID_VERIFIER;
         }
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });

#else
   BOTAN_UNUSED(cert_store,cert,key);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

// NOTE: *DOES NOT* return boolean success code
int botan_x509_cert_store_sql_remove_key(
   botan_x509_cert_store_t cert_store,
   botan_privkey_t key) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

   return BOTAN_FFI_VISIT(cert_store, [=](auto& obj) {
      if (auto store = dynamic_cast<Botan::Certificate_Store_In_SQL*>(&obj)) {
         store->remove_key(safe_get(key));
         return BOTAN_FFI_SUCCESS;
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });

#else
   BOTAN_UNUSED(cert_store,key);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_store_sql_revoke_cert(
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert,
   uint32_t crl_code,
   uint64_t time) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

   return BOTAN_FFI_VISIT(cert_store, [=](auto& obj) {
      if (auto store = dynamic_cast<Botan::Certificate_Store_In_SQL*>(&obj)) {
         auto seconds = std::chrono::seconds(time);
         auto duration = std::chrono::duration_cast<std::chrono::system_clock::time_point::duration>(seconds);
         auto tp = std::chrono::system_clock::time_point(duration);
         store->revoke_cert(safe_get(cert),static_cast<Botan::CRL_Code>(crl_code),Botan::X509_Time(tp));
         return BOTAN_FFI_SUCCESS;
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });

#else
   BOTAN_UNUSED(cert_store,cert,crl_code,time);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_store_sql_affirm_cert(
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

   return BOTAN_FFI_VISIT(cert_store, [=](auto& obj) {
      if (auto store = dynamic_cast<Botan::Certificate_Store_In_SQL*>(&obj)) {
         store->affirm_cert(safe_get(cert));
         return BOTAN_FFI_SUCCESS;
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });

#else
   BOTAN_UNUSED(cert_store,cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

// NOTE: Ditto notes on double-pointer
int botan_x509_cert_store_sql_generate_crls(
   botan_x509_crl_t** crls, size_t* crls_len,
   botan_x509_cert_store_t cert_store) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

   if(crls == nullptr || crls_len == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(cert_store, [=](auto& obj) {
      if (auto store = dynamic_cast<Botan::Certificate_Store_In_SQL*>(&obj)) {
         auto result = store->generate_crls();
         // TODO:
         // *crls = ...
         // *crls_len = result.size;
         // return BOTAN_FFI_SUCCESS;
         return BOTAN_FFI_ERROR_INTERNAL_ERROR;
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });

#else
   BOTAN_UNUSED(crls,crls_len,cert_store);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/**
* SQLite3 Certificate Store
*/

int botan_x509_cert_store_sqlite3_create(
   botan_x509_cert_store_t* cert_store,
   const char* db_path,
   const char* passwd,
   botan_rng_t rng,
   const char* table_prefix) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

   if(cert_store == nullptr || db_path == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {

      // auto cert_store_obj = std::make_unique<Botan::Certificate_Store_In_SQLite>(
      //    std::string(db_path),
      //    passwd ? passwd : "",
      //    safe_get(rng),
      //    table_prefix ? table_prefix : "");
      // *cert_store = new botan_x509_cert_store_struct(std::move(cert_store_obj));
      // return BOTAN_FFI_SUCCESS;

      // NOTE: Can't find / include <botan/sqlite3.h> nor <botan/certstor_sqlite.h>?
      // Thus, no access to Certificate_Store_In_SQLite
      BOTAN_UNUSED(passwd,rng,table_prefix);
      return BOTAN_FFI_ERROR_INTERNAL_ERROR;

   });

#else
   BOTAN_UNUSED(cert_store,db_path,passwd,rng,table_prefix);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/**
* System Certificate Store
*/

int botan_x509_cert_store_system_create(
   botan_x509_cert_store_t* cert_store) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

   if(cert_store == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto cert_store_obj = std::make_unique<Botan::System_Certificate_Store>();
      *cert_store = new botan_x509_cert_store_struct(std::move(cert_store_obj));
      return BOTAN_FFI_SUCCESS;
   });

#else
   BOTAN_UNUSED(cert_store);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/**
* MacOS Certificate Store
*/

int botan_x509_cert_store_macos_create(
   botan_x509_cert_store_t* cert_store) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   BOTAN_UNUSED(cert_store);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(cert_store);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/**
* Windows Certificate Store
*/

int botan_x509_cert_store_windows_create(
   botan_x509_cert_store_t* cert_store) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   BOTAN_UNUSED(cert_store);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(cert_store);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

/*
* X.509 Path validation
**************************/

BOTAN_FFI_DECLARE_STRUCT(botan_x509_path_validation_restrictions_struct, Botan::Path_Validation_Restrictions, 0xb070e8a9);
BOTAN_FFI_DECLARE_STRUCT(botan_x509_path_validation_result_struct, Botan::Path_Validation_Result, 0xe7d9c255);

int botan_x509_path_validation_restrictions_destroy(botan_x509_path_validation_restrictions_t restrictions) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(restrictions);
#else
   BOTAN_UNUSED(restrictions);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_path_validation_result_destroy(botan_x509_path_validation_result_t result) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(result);
#else
   BOTAN_UNUSED(result);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_path_validation_restrictions_create(
   botan_x509_path_validation_restrictions_t* restrictions,
   bool require_rev,
   size_t minimum_key_strength,
   bool ocsp_all_intermediates,
   uint64_t max_ocsp_age,
   botan_x509_cert_store_t trusted_ocsp_responders) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   BOTAN_UNUSED(restrictions,require_rev,minimum_key_strength);
   BOTAN_UNUSED(ocsp_all_intermediates,max_ocsp_age,trusted_ocsp_responders);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(restrictions,require_rev,minimum_key_strength);
   BOTAN_UNUSED(ocsp_all_intermediates,max_ocsp_age,trusted_ocsp_responders);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

// NOTE: This needs more than IF BOTAN_HAS_X509_CERTIFICATES
// It needs the IF HTTP_UTIL as well?
int botan_x509_path_validate(
   botan_x509_path_validation_result_t* result,
   botan_x509_cert_t end_cert,
   botan_x509_path_validation_restrictions_t* restrictions,
   botan_x509_cert_store_t cert_store,
   const char* hostname,
   unsigned int usage,
   uint64_t validation_time,
   uint64_t ocsp_timeout,
   void* ocsp_resp) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   BOTAN_UNUSED(result,end_cert,restrictions,cert_store,hostname);
   BOTAN_UNUSED(usage,validation_time,ocsp_timeout,ocsp_resp);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(result,end_cert,restrictions,cert_store,hostname);
   BOTAN_UNUSED(usage,validation_time,ocsp_timeout,ocsp_resp);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_path_validation_result_successful_validation(
   botan_x509_path_validation_result_t pvr) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   BOTAN_UNUSED(pvr);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(pvr);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_path_validation_result_result_string(
   char* result_string,
   botan_x509_path_validation_result_t pvr) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   BOTAN_UNUSED(result_string,pvr);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(result_string,pvr);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_path_validation_result_trust_root(
   botan_x509_cert_t* trust_root,
   botan_x509_path_validation_result_t pvr) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   BOTAN_UNUSED(trust_root,pvr);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(trust_root,pvr);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_path_validation_result_cert_path(
   botan_x509_cert_t** cert_path, size_t* cert_path_len,
   botan_x509_path_validation_result_t pvr) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   BOTAN_UNUSED(cert_path,cert_path_len,pvr);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(cert_path,cert_path_len,pvr);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_path_validation_result_status_code(
   int* status_code,
   botan_x509_path_validation_result_t pvr) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   BOTAN_UNUSED(status_code,pvr);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(status_code,pvr);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_path_validation_result_all_status_codes(
   int* status_codes, size_t* status_codes_len,
   botan_x509_path_validation_result_t pvr) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   BOTAN_UNUSED(status_codes,status_codes_len,pvr);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(status_codes,status_codes_len,pvr);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_path_validation_result_trusted_hashes(
   char** trusted_hashes, size_t* trusted_hashes_len,
   botan_x509_path_validation_result_t pvr) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   BOTAN_UNUSED(trusted_hashes,trusted_hashes_len,pvr);
   return BOTAN_FFI_ERROR_INTERNAL_ERROR;
#else
   BOTAN_UNUSED(trusted_hashes,trusted_hashes_len,pvr);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

} // extern "C"

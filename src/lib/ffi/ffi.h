/*
* FFI (C89 API)
* (C) 2015,2017 Jack Lloyd
* (C) 2021 René Fischer
* (C) 2023 Leo Dillinger
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FFI_H_
#define BOTAN_FFI_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
This header exports some of botan's functionality via a C89 interface. This API
is uesd by the Python, OCaml, Rust, Ruby, and Haskell bindings via those languages
respective ctypes/FFI libraries.

The API is intended to be as easy as possible to call from other
languages, which often have easy ways to call C, because C. But some C
code is easier to deal with than others, so to make things easy this
API follows a few simple rules:

- All interactions are via pointers to opaque structs. No need to worry about
  structure padding issues and the like.

- All functions return an int error code (except the version calls, which are
  assumed to always have something to say).

- Use simple types: size_t for lengths, const char* NULL terminated strings,
  uint8_t for binary.

- No ownership of memory transfers across the API boundary. The API will
  consume data from const pointers, and will produce output by writing to
  buffers provided by (and allocated by) the caller.

- If exporting a value (a string or a blob) the function takes a pointer to the
  output array and a read/write pointer to the length. If the length is insufficient, an
  error is returned. So passing nullptr/0 allows querying the final value.

  Typically there is also a function which allows querying the expected output
  length of a function, for example `botan_hash_output_length` allows knowing in
  advance the expected size for `botan_hash_final`. Some of these are exact,
  while others such as `botan_pk_op_decrypt_output_length` only provide an upper
  bound.

  The big exception to this currently is the various functions which serialize
  public and private keys, where there are currently no function that can
  estimate the serialized size. Here view functions are used; see the handbook
  for further details.

 TODO:
 - Doxygen comments for all functions/params
 - TLS
*/

#include <botan/build.h>
#include <stddef.h>
#include <stdint.h>

/**
* Notes the version that this FFI function was first added
*/
#define BOTAN_FFI_EXPORT(maj, min) BOTAN_DLL

#if !defined(BOTAN_NO_DEPRECATED_WARNINGS)
   #if defined(__has_attribute)
      #if __has_attribute(deprecated)
         #define BOTAN_FFI_DEPRECATED(msg) __attribute__((deprecated(msg)))
      #endif
   #elif defined(_MSC_VER)
      #define BOTAN_FFI_DEPRECATED(msg) __declspec(deprecated(msg))
   #endif
#endif

#if !defined(BOTAN_FFI_DEPRECATED)
   #define BOTAN_FFI_DEPRECATED(msg) /**/
#endif

/**
* Error codes
*
* If you add a new value here be sure to also add it in
* botan_error_description
*/
enum BOTAN_FFI_ERROR {
   BOTAN_FFI_SUCCESS = 0,
   BOTAN_FFI_INVALID_VERIFIER = 1,

   BOTAN_FFI_ERROR_INVALID_INPUT = -1,
   BOTAN_FFI_ERROR_BAD_MAC = -2,

   BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE = -10,
   BOTAN_FFI_ERROR_STRING_CONVERSION_ERROR = -11,

   BOTAN_FFI_ERROR_EXCEPTION_THROWN = -20,
   BOTAN_FFI_ERROR_OUT_OF_MEMORY = -21,
   BOTAN_FFI_ERROR_SYSTEM_ERROR = -22,
   BOTAN_FFI_ERROR_INTERNAL_ERROR = -23,

   BOTAN_FFI_ERROR_BAD_FLAG = -30,
   BOTAN_FFI_ERROR_NULL_POINTER = -31,
   BOTAN_FFI_ERROR_BAD_PARAMETER = -32,
   BOTAN_FFI_ERROR_KEY_NOT_SET = -33,
   BOTAN_FFI_ERROR_INVALID_KEY_LENGTH = -34,
   BOTAN_FFI_ERROR_INVALID_OBJECT_STATE = -35,

   BOTAN_FFI_ERROR_NOT_IMPLEMENTED = -40,
   BOTAN_FFI_ERROR_INVALID_OBJECT = -50,

   BOTAN_FFI_ERROR_TLS_ERROR = -75,
   BOTAN_FFI_ERROR_HTTP_ERROR = -76,
   BOTAN_FFI_ERROR_ROUGHTIME_ERROR = -77,

   BOTAN_FFI_ERROR_UNKNOWN_ERROR = -100,
};

typedef void* botan_view_ctx;

/**
* Viewer function for binary data
*
* @param view_ctx some application context
* @param data the binary data
* @param len the length of data in bytes
*/
typedef int (*botan_view_bin_fn)(botan_view_ctx view_ctx, const uint8_t* data, size_t len);

/**
* Viewer function for string data
*
* @param view_ctx some application context
* @param str the null terminated string
* @param len the length of string *including* the null terminator
*/
typedef int (*botan_view_str_fn)(botan_view_ctx view_ctx, const char* str, size_t len);

/**
* Convert an error code into a string. Returns "Unknown error"
* if the error code is not a known one.
*/
BOTAN_FFI_EXPORT(2, 8) const char* botan_error_description(int err);

/**
* Return the message of the last exception caught in this thread.
*
* This pointer can/will be reallocated or overwritten the next time
* this thread calls any other Botan FFI function and must be copied
* to persistent storage first.
*/
BOTAN_FFI_EXPORT(3, 0) const char* botan_error_last_exception_message(void);

/**
* Return the version of the currently supported FFI API. This is
* expressed in the form YYYYMMDD of the release date of this version
* of the API.
*/
BOTAN_FFI_EXPORT(2, 0) uint32_t botan_ffi_api_version(void);

/**
* Return 0 (ok) if the version given is one this library supports.
* botan_ffi_supports_api(botan_ffi_api_version()) will always return 0.
*/
BOTAN_FFI_EXPORT(2, 0) int botan_ffi_supports_api(uint32_t api_version);

/**
* Return a free-form version string, e.g., 2.0.0
*/
BOTAN_FFI_EXPORT(2, 0) const char* botan_version_string(void);

/**
* Return the major version of the library
*/
BOTAN_FFI_EXPORT(2, 0) uint32_t botan_version_major(void);

/**
* Return the minor version of the library
*/
BOTAN_FFI_EXPORT(2, 0) uint32_t botan_version_minor(void);

/**
* Return the patch version of the library
*/
BOTAN_FFI_EXPORT(2, 0) uint32_t botan_version_patch(void);

/**
* Return the date this version was released as
* an integer, or 0 if an unreleased version
*/
BOTAN_FFI_EXPORT(2, 0) uint32_t botan_version_datestamp(void);

/**
* Returns 0 if x[0..len] == y[0..len], or otherwise -1
*/
BOTAN_FFI_EXPORT(2, 3) int botan_constant_time_compare(const uint8_t* x, const uint8_t* y, size_t len);

/**
* Deprecated equivalent to botan_constant_time_compare
*/
BOTAN_FFI_DEPRECATED("Use botan_constant_time_compare")
BOTAN_FFI_EXPORT(2, 0) int botan_same_mem(const uint8_t* x, const uint8_t* y, size_t len);

/**
* Clear out memory using a system specific approach to bypass elision by the
* compiler (currently using RtlSecureZeroMemory or tricks with volatile pointers).
*/
BOTAN_FFI_EXPORT(2, 2) int botan_scrub_mem(void* mem, size_t bytes);

#define BOTAN_FFI_HEX_LOWER_CASE 1

/**
* Perform hex encoding
* @param x is some binary data
* @param len length of x in bytes
* @param out an array of at least x*2 bytes
* @param flags flags out be upper or lower case?
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_hex_encode(const uint8_t* x, size_t len, char* out, uint32_t flags);

/**
* Perform hex decoding
* @param hex_str a string of hex chars (whitespace is ignored)
* @param in_len the length of hex_str
* @param out the output buffer should be at least strlen(hex_str)/2 bytes
* @param out_len the size of the output buffer on input, set to the number of bytes written
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 3) int botan_hex_decode(const char* hex_str, size_t in_len, uint8_t* out, size_t* out_len);

/**
* Perform base64 encoding
*/
BOTAN_FFI_EXPORT(2, 3) int botan_base64_encode(const uint8_t* x, size_t len, char* out, size_t* out_len);

/**
* Perform base64 decoding
*/
BOTAN_FFI_EXPORT(2, 3) int botan_base64_decode(const char* base64_str, size_t in_len, uint8_t* out, size_t* out_len);

/**
* RNG type
*/
typedef struct botan_rng_struct* botan_rng_t;

/**
* Initialize a random number generator object
* @param rng rng object
* @param rng_type type of the rng, possible values:
*    "system": system RNG
*    "user": userspace RNG
*    "user-threadsafe": userspace RNG, with internal locking
*    "rdrand": directly read RDRAND
* Set rng_type to null to let the library choose some default.
*/
BOTAN_FFI_EXPORT(2, 0) int botan_rng_init(botan_rng_t* rng, const char* rng_type);

/**
* Initialize a custom random number generator from a set of callback functions
* @param rng_out rng object to create
* @param rng_name name of the rng
* @param context An application-specific context passed to the callback functions
* @param get_cb Callback for getting random bytes from the rng, return 0 for success
* @param add_entropy_cb Callback for adding entropy to the rng, return 0 for success, may be NULL
* @param destroy_cb Callback called when rng is destroyed, may be NULL
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_rng_init_custom(botan_rng_t* rng_out,
                          const char* rng_name,
                          void* context,
                          int (*get_cb)(void* context, uint8_t* out, size_t out_len),
                          int (*add_entropy_cb)(void* context, const uint8_t input[], size_t length),
                          void (*destroy_cb)(void* context));

/**
* Get random bytes from a random number generator
* @param rng rng object
* @param out output buffer of size out_len
* @param out_len number of requested bytes
* @return 0 on success, negative on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_rng_get(botan_rng_t rng, uint8_t* out, size_t out_len);

/**
* Get random bytes from system random number generator
* @param out output buffer of size out_len
* @param out_len number of requested bytes
* @return 0 on success, negative on failure
*/
BOTAN_FFI_EXPORT(3, 0) int botan_system_rng_get(uint8_t* out, size_t out_len);

/**
* Reseed a random number generator
* Uses the System_RNG as a seed generator.
*
* @param rng rng object
* @param bits number of bits to reseed with
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_rng_reseed(botan_rng_t rng, size_t bits);

/**
* Reseed a random number generator
*
* @param rng rng object
* @param source_rng the rng that will be read from
* @param bits number of bits to reseed with
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8) int botan_rng_reseed_from_rng(botan_rng_t rng, botan_rng_t source_rng, size_t bits);

/**
* Add some seed material to a random number generator
*
* @param rng rng object
* @param entropy the data to add
* @param entropy_len length of entropy buffer
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 8) int botan_rng_add_entropy(botan_rng_t rng, const uint8_t* entropy, size_t entropy_len);

/**
* Frees all resources of the random number generator object
* @param rng rng object
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_rng_destroy(botan_rng_t rng);

/*
* Hash type
*/
typedef struct botan_hash_struct* botan_hash_t;

/**
* Initialize a hash function object
* @param hash hash object
* @param hash_name name of the hash function, e.g., "SHA-384"
* @param flags should be 0 in current API revision, all other uses are reserved
*       and return BOTAN_FFI_ERROR_BAD_FLAG
*/
BOTAN_FFI_EXPORT(2, 0) int botan_hash_init(botan_hash_t* hash, const char* hash_name, uint32_t flags);

/**
* Copy the state of a hash function object
* @param dest destination hash object
* @param source source hash object
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 2) int botan_hash_copy_state(botan_hash_t* dest, botan_hash_t source);

/**
* Writes the output length of the hash function to *output_length
* @param hash hash object
* @param output_length output buffer to hold the hash function output length
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_hash_output_length(botan_hash_t hash, size_t* output_length);

/**
* Writes the block size of the hash function to *block_size
* @param hash hash object
* @param block_size output buffer to hold the hash function output length
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 2) int botan_hash_block_size(botan_hash_t hash, size_t* block_size);

/**
* Send more input to the hash function
* @param hash hash object
* @param in input buffer
* @param in_len number of bytes to read from the input buffer
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_hash_update(botan_hash_t hash, const uint8_t* in, size_t in_len);

/**
* Finalizes the hash computation and writes the output to
* out[0:botan_hash_output_length()] then reinitializes for computing
* another digest as if botan_hash_clear had been called.
* @param hash hash object
* @param out output buffer
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_hash_final(botan_hash_t hash, uint8_t out[]);

/**
* Reinitializes the state of the hash computation. A hash can
* be computed (with update/final) immediately.
* @param hash hash object
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_hash_clear(botan_hash_t hash);

/**
* Frees all resources of the hash object
* @param hash hash object
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_hash_destroy(botan_hash_t hash);

/**
* Get the name of this hash function
* @param hash the object to read
* @param name output buffer
* @param name_len on input, the length of buffer, on success the number of bytes written
*/
BOTAN_FFI_EXPORT(2, 8) int botan_hash_name(botan_hash_t hash, char* name, size_t* name_len);

/*
* Message Authentication type
*/
typedef struct botan_mac_struct* botan_mac_t;

/**
* Initialize a message authentication code object
* @param mac mac object
* @param mac_name name of the hash function, e.g., "HMAC(SHA-384)"
* @param flags should be 0 in current API revision, all other uses are reserved
*       and return a negative value (error code)
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_mac_init(botan_mac_t* mac, const char* mac_name, uint32_t flags);

/**
* Writes the output length of the message authentication code to *output_length
* @param mac mac object
* @param output_length output buffer to hold the MAC output length
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_mac_output_length(botan_mac_t mac, size_t* output_length);

/**
* Sets the key on the MAC
* @param mac mac object
* @param key buffer holding the key
* @param key_len size of the key buffer in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_mac_set_key(botan_mac_t mac, const uint8_t* key, size_t key_len);

/**
* Sets the nonce on the MAC
* @param mac mac object
* @param nonce buffer holding the key
* @param nonce_len size of the key buffer in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(3, 0) int botan_mac_set_nonce(botan_mac_t mac, const uint8_t* nonce, size_t nonce_len);

/**
* Send more input to the message authentication code
* @param mac mac object
* @param buf input buffer
* @param len number of bytes to read from the input buffer
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_mac_update(botan_mac_t mac, const uint8_t* buf, size_t len);

/**
* Finalizes the MAC computation and writes the output to
* out[0:botan_mac_output_length()] then reinitializes for computing
* another MAC as if botan_mac_clear had been called.
* @param mac mac object
* @param out output buffer
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_mac_final(botan_mac_t mac, uint8_t out[]);

/**
* Reinitializes the state of the MAC computation. A MAC can
* be computed (with update/final) immediately.
* @param mac mac object
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_mac_clear(botan_mac_t mac);

/**
* Get the name of this MAC
* @param mac the object to read
* @param name output buffer
* @param name_len on input, the length of buffer, on success the number of bytes written
*/
BOTAN_FFI_EXPORT(2, 8) int botan_mac_name(botan_mac_t mac, char* name, size_t* name_len);

/**
* Get the key length limits of this auth code
* @param mac the object to read
* @param out_minimum_keylength if non-NULL, will be set to minimum keylength of MAC
* @param out_maximum_keylength if non-NULL, will be set to maximum keylength of MAC
* @param out_keylength_modulo if non-NULL will be set to byte multiple of valid keys
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_mac_get_keyspec(botan_mac_t mac,
                          size_t* out_minimum_keylength,
                          size_t* out_maximum_keylength,
                          size_t* out_keylength_modulo);

/**
* Frees all resources of the MAC object
* @param mac mac object
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_mac_destroy(botan_mac_t mac);

/*
* Cipher modes
*/
typedef struct botan_cipher_struct* botan_cipher_t;

#define BOTAN_CIPHER_INIT_FLAG_MASK_DIRECTION 1
#define BOTAN_CIPHER_INIT_FLAG_ENCRYPT 0
#define BOTAN_CIPHER_INIT_FLAG_DECRYPT 1

/**
* Initialize a cipher object
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_init(botan_cipher_t* cipher, const char* name, uint32_t flags);

/**
* Return the name of the cipher object
*/
BOTAN_FFI_EXPORT(2, 8) int botan_cipher_name(botan_cipher_t cipher, char* name, size_t* name_len);

/**
* Return the output length of this cipher, for a particular input length.
*/
BOTAN_FFI_EXPORT(2, 8) int botan_cipher_output_length(botan_cipher_t cipher, size_t in_len, size_t* out_len);

/**
* Return if the specified nonce length is valid for this cipher
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_valid_nonce_length(botan_cipher_t cipher, size_t nl);

/**
* Get the tag length of the cipher (0 for non-AEAD modes)
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_get_tag_length(botan_cipher_t cipher, size_t* tag_size);

/**
* Get the default nonce length of this cipher
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_get_default_nonce_length(botan_cipher_t cipher, size_t* nl);

/**
* Return the update granularity of the cipher; botan_cipher_update must be
* called with blocks of this size, except for the final.
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_get_update_granularity(botan_cipher_t cipher, size_t* ug);

/**
* Return the ideal update granularity of the cipher. This is some multiple of the
* update granularity, reflecting possibilities for optimization.
*/
BOTAN_FFI_EXPORT(3, 0) int botan_cipher_get_ideal_update_granularity(botan_cipher_t cipher, size_t* ug);

/**
* Get information about the key lengths. Prefer botan_cipher_get_keyspec
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_cipher_query_keylen(botan_cipher_t, size_t* out_minimum_keylength, size_t* out_maximum_keylength);

/**
* Get information about the supported key lengths.
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_cipher_get_keyspec(botan_cipher_t, size_t* min_keylen, size_t* max_keylen, size_t* mod_keylen);

/**
* Set the key for this cipher object
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_set_key(botan_cipher_t cipher, const uint8_t* key, size_t key_len);

/**
* Reset the message specific state for this cipher.
* Without resetting the keys, this resets the nonce, and any state
* associated with any message bits that have been processed so far.
*
* It is conceptually equivalent to calling botan_cipher_clear followed
* by botan_cipher_set_key with the original key.
*/
BOTAN_FFI_EXPORT(2, 8) int botan_cipher_reset(botan_cipher_t cipher);

/**
* Set the associated data. Will fail if cipher is not an AEAD
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_set_associated_data(botan_cipher_t cipher, const uint8_t* ad, size_t ad_len);

/**
* Begin processing a new message using the provided nonce
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_start(botan_cipher_t cipher, const uint8_t* nonce, size_t nonce_len);

#define BOTAN_CIPHER_UPDATE_FLAG_FINAL (1U << 0)

/**
* Encrypt some data
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_cipher_update(botan_cipher_t cipher,
                        uint32_t flags,
                        uint8_t output[],
                        size_t output_size,
                        size_t* output_written,
                        const uint8_t input_bytes[],
                        size_t input_size,
                        size_t* input_consumed);

/**
* Reset the key, nonce, AD and all other state on this cipher object
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_clear(botan_cipher_t hash);

/**
* Destroy the cipher object
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_cipher_destroy(botan_cipher_t cipher);

/*
* Derive a key from a passphrase for a number of iterations
* @param pbkdf_algo PBKDF algorithm, e.g., "PBKDF2(SHA-256)"
* @param out buffer to store the derived key, must be of out_len bytes
* @param out_len the desired length of the key to produce
* @param passphrase the password to derive the key from
* @param salt a randomly chosen salt
* @param salt_len length of salt in bytes
* @param iterations the number of iterations to use (use 10K or more)
* @return 0 on success, a negative value on failure
*
* Deprecated: use
*  botan_pwdhash(pbkdf_algo, iterations, 0, 0, out, out_len,
*                passphrase, 0, salt, salt_len);
*/
BOTAN_FFI_DEPRECATED("Use botan_pwdhash")
BOTAN_FFI_EXPORT(2, 0)
int botan_pbkdf(const char* pbkdf_algo,
                uint8_t out[],
                size_t out_len,
                const char* passphrase,
                const uint8_t salt[],
                size_t salt_len,
                size_t iterations);

/**
* Derive a key from a passphrase, running until msec time has elapsed.
* @param pbkdf_algo PBKDF algorithm, e.g., "PBKDF2(SHA-256)"
* @param out buffer to store the derived key, must be of out_len bytes
* @param out_len the desired length of the key to produce
* @param passphrase the password to derive the key from
* @param salt a randomly chosen salt
* @param salt_len length of salt in bytes
* @param milliseconds_to_run if iterations is zero, then instead the PBKDF is
*        run until milliseconds_to_run milliseconds has passed
* @param out_iterations_used set to the number iterations executed
* @return 0 on success, a negative value on failure
*
* Deprecated: use
*
* botan_pwdhash_timed(pbkdf_algo,
*                     static_cast<uint32_t>(ms_to_run),
*                     iterations_used,
*                     nullptr,
*                     nullptr,
*                     out, out_len,
*                     password, 0,
*                     salt, salt_len);
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_pbkdf_timed(const char* pbkdf_algo,
                      uint8_t out[],
                      size_t out_len,
                      const char* passphrase,
                      const uint8_t salt[],
                      size_t salt_len,
                      size_t milliseconds_to_run,
                      size_t* out_iterations_used);

/*
* Derive a key from a passphrase
* @param algo PBKDF algorithm, e.g., "PBKDF2(SHA-256)" or "Scrypt"
* @param param1 the first PBKDF algorithm parameter
* @param param2 the second PBKDF algorithm parameter (may be zero if unneeded)
* @param param3 the third PBKDF algorithm parameter (may be zero if unneeded)
* @param out buffer to store the derived key, must be of out_len bytes
* @param out_len the desired length of the key to produce
* @param passphrase the password to derive the key from
* @param passphrase_len if > 0, specifies length of password. If len == 0, then
*        strlen will be called on passphrase to compute the length.
* @param salt a randomly chosen salt
* @param salt_len length of salt in bytes
* @return 0 on success, a negative value on failure
*/
int BOTAN_FFI_EXPORT(2, 8) botan_pwdhash(const char* algo,
                                         size_t param1,
                                         size_t param2,
                                         size_t param3,
                                         uint8_t out[],
                                         size_t out_len,
                                         const char* passphrase,
                                         size_t passphrase_len,
                                         const uint8_t salt[],
                                         size_t salt_len);

/*
* Derive a key from a passphrase
* @param pbkdf_algo PBKDF algorithm, e.g., "Scrypt" or "PBKDF2(SHA-256)"
* @param msec the desired runtime in milliseconds
* @param param1 will be set to the first password hash parameter
* @param param2 will be set to the second password hash parameter
* @param param3 will be set to the third password hash parameter
* @param out buffer to store the derived key, must be of out_len bytes
* @param out_len the desired length of the key to produce
* @param passphrase the password to derive the key from
* @param passphrase_len if > 0, specifies length of password. If len == 0, then
*        strlen will be called on passphrase to compute the length.
* @param salt a randomly chosen salt
* @param salt_len length of salt in bytes
* @return 0 on success, a negative value on failure
*/
int BOTAN_FFI_EXPORT(2, 8) botan_pwdhash_timed(const char* algo,
                                               uint32_t msec,
                                               size_t* param1,
                                               size_t* param2,
                                               size_t* param3,
                                               uint8_t out[],
                                               size_t out_len,
                                               const char* passphrase,
                                               size_t passphrase_len,
                                               const uint8_t salt[],
                                               size_t salt_len);

/**
* Derive a key using scrypt
* Deprecated; use
* botan_pwdhash("Scrypt", N, r, p, out, out_len, password, 0, salt, salt_len);
*/
BOTAN_FFI_DEPRECATED("Use botan_pwdhash")
BOTAN_FFI_EXPORT(2, 8)
int botan_scrypt(uint8_t out[],
                 size_t out_len,
                 const char* passphrase,
                 const uint8_t salt[],
                 size_t salt_len,
                 size_t N,
                 size_t r,
                 size_t p);

/**
* Derive a key
* @param kdf_algo KDF algorithm, e.g., "SP800-56C"
* @param out buffer holding the derived key, must be of length out_len
* @param out_len the desired output length in bytes
* @param secret the secret input
* @param secret_len size of secret in bytes
* @param salt a diversifier
* @param salt_len size of salt in bytes
* @param label purpose for the derived keying material
* @param label_len size of label in bytes
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_kdf(const char* kdf_algo,
              uint8_t out[],
              size_t out_len,
              const uint8_t secret[],
              size_t secret_len,
              const uint8_t salt[],
              size_t salt_len,
              const uint8_t label[],
              size_t label_len);

/*
* Raw Block Cipher (PRP) interface
*/
typedef struct botan_block_cipher_struct* botan_block_cipher_t;

/**
* Initialize a block cipher object
*/
BOTAN_FFI_EXPORT(2, 1) int botan_block_cipher_init(botan_block_cipher_t* bc, const char* cipher_name);

/**
* Destroy a block cipher object
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 1) int botan_block_cipher_destroy(botan_block_cipher_t bc);

/**
* Reinitializes the block cipher
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 1) int botan_block_cipher_clear(botan_block_cipher_t bc);

/**
* Set the key for a block cipher instance
*/
BOTAN_FFI_EXPORT(2, 1) int botan_block_cipher_set_key(botan_block_cipher_t bc, const uint8_t key[], size_t len);

/**
* Return the positive block size of this block cipher, or negative to
* indicate an error
*/
BOTAN_FFI_EXPORT(2, 1) int botan_block_cipher_block_size(botan_block_cipher_t bc);

/**
* Encrypt one or more blocks with the cipher
*/
BOTAN_FFI_EXPORT(2, 1)
int botan_block_cipher_encrypt_blocks(botan_block_cipher_t bc, const uint8_t in[], uint8_t out[], size_t blocks);

/**
* Decrypt one or more blocks with the cipher
*/
BOTAN_FFI_EXPORT(2, 1)
int botan_block_cipher_decrypt_blocks(botan_block_cipher_t bc, const uint8_t in[], uint8_t out[], size_t blocks);

/**
* Get the name of this block cipher
* @param cipher the object to read
* @param name output buffer
* @param name_len on input, the length of buffer, on success the number of bytes written
*/
BOTAN_FFI_EXPORT(2, 8) int botan_block_cipher_name(botan_block_cipher_t cipher, char* name, size_t* name_len);

/**
* Get the key length limits of this block cipher
* @param cipher the object to read
* @param out_minimum_keylength if non-NULL, will be set to minimum keylength of cipher
* @param out_maximum_keylength if non-NULL, will be set to maximum keylength of cipher
* @param out_keylength_modulo if non-NULL will be set to byte multiple of valid keys
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_block_cipher_get_keyspec(botan_block_cipher_t cipher,
                                   size_t* out_minimum_keylength,
                                   size_t* out_maximum_keylength,
                                   size_t* out_keylength_modulo);

/*
* Multiple precision integers (MPI)
*/
typedef struct botan_mp_struct* botan_mp_t;

/**
* Initialize an MPI
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_init(botan_mp_t* mp);

/**
* Destroy (deallocate) an MPI
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_destroy(botan_mp_t mp);

/**
* Convert the MPI to a hex string. Writes botan_mp_num_bytes(mp)*2 + 1 bytes
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_to_hex(botan_mp_t mp, char* out);

/**
* Convert the MPI to a string. Currently base == 10 and base == 16 are supported.
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_to_str(botan_mp_t mp, uint8_t base, char* out, size_t* out_len);

/**
* Set the MPI to zero
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_clear(botan_mp_t mp);

/**
* Set the MPI value from an int
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_set_from_int(botan_mp_t mp, int initial_value);

/**
* Set the MPI value from another MP object
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_set_from_mp(botan_mp_t dest, botan_mp_t source);

/**
* Set the MPI value from a string
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_set_from_str(botan_mp_t dest, const char* str);

/**
* Set the MPI value from a string with arbitrary radix.
* For arbitrary being 10 or 16.
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_set_from_radix_str(botan_mp_t dest, const char* str, size_t radix);

/**
* Return the number of significant bits in the MPI
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_num_bits(botan_mp_t n, size_t* bits);

/**
* Return the number of significant bytes in the MPI
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_num_bytes(botan_mp_t n, size_t* bytes);

/*
* Convert the MPI to a big-endian binary string. Writes botan_mp_num_bytes to vec
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_to_bin(botan_mp_t mp, uint8_t vec[]);

/*
* Set an MP to the big-endian binary value
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_from_bin(botan_mp_t mp, const uint8_t vec[], size_t vec_len);

/*
* Convert the MPI to a uint32_t, if possible. Fails if MPI is negative or too large.
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_to_uint32(botan_mp_t mp, uint32_t* val);

/**
* This function should have been named mp_is_non_negative. Returns 1
* iff mp is greater than *or equal to* zero. Use botan_mp_is_negative
* to detect negative numbers, botan_mp_is_zero to check for zero.
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_is_positive(botan_mp_t mp);

/**
* Return 1 iff mp is less than 0
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_is_negative(botan_mp_t mp);

BOTAN_FFI_EXPORT(2, 1) int botan_mp_flip_sign(botan_mp_t mp);

BOTAN_FFI_EXPORT(2, 1) int botan_mp_is_zero(botan_mp_t mp);

BOTAN_FFI_DEPRECATED("Use botan_mp_get_bit(0)") BOTAN_FFI_EXPORT(2, 1) int botan_mp_is_odd(botan_mp_t mp);
BOTAN_FFI_DEPRECATED("Use botan_mp_get_bit(0)") BOTAN_FFI_EXPORT(2, 1) int botan_mp_is_even(botan_mp_t mp);

BOTAN_FFI_EXPORT(2, 8) int botan_mp_add_u32(botan_mp_t result, botan_mp_t x, uint32_t y);
BOTAN_FFI_EXPORT(2, 8) int botan_mp_sub_u32(botan_mp_t result, botan_mp_t x, uint32_t y);

BOTAN_FFI_EXPORT(2, 1) int botan_mp_add(botan_mp_t result, botan_mp_t x, botan_mp_t y);
BOTAN_FFI_EXPORT(2, 1) int botan_mp_sub(botan_mp_t result, botan_mp_t x, botan_mp_t y);
BOTAN_FFI_EXPORT(2, 1) int botan_mp_mul(botan_mp_t result, botan_mp_t x, botan_mp_t y);

BOTAN_FFI_EXPORT(2, 1)
int botan_mp_div(botan_mp_t quotient, botan_mp_t remainder, botan_mp_t x, botan_mp_t y);

BOTAN_FFI_EXPORT(2, 1)
int botan_mp_mod_mul(botan_mp_t result, botan_mp_t x, botan_mp_t y, botan_mp_t mod);

/*
* Returns 0 if x != y
* Returns 1 if x == y
* Returns negative number on error
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_equal(botan_mp_t x, botan_mp_t y);

/*
* Sets *result to comparison result:
* -1 if x < y, 0 if x == y, 1 if x > y
* Returns negative number on error or zero on success
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_cmp(int* result, botan_mp_t x, botan_mp_t y);

/*
* Swap two botan_mp_t
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_swap(botan_mp_t x, botan_mp_t y);

/* Return (base^exponent) % modulus */
BOTAN_FFI_EXPORT(2, 1)
int botan_mp_powmod(botan_mp_t out, botan_mp_t base, botan_mp_t exponent, botan_mp_t modulus);

BOTAN_FFI_EXPORT(2, 1) int botan_mp_lshift(botan_mp_t out, botan_mp_t in, size_t shift);
BOTAN_FFI_EXPORT(2, 1) int botan_mp_rshift(botan_mp_t out, botan_mp_t in, size_t shift);

BOTAN_FFI_EXPORT(2, 1) int botan_mp_mod_inverse(botan_mp_t out, botan_mp_t in, botan_mp_t modulus);

BOTAN_FFI_EXPORT(2, 1) int botan_mp_rand_bits(botan_mp_t rand_out, botan_rng_t rng, size_t bits);

BOTAN_FFI_EXPORT(2, 1)
int botan_mp_rand_range(botan_mp_t rand_out, botan_rng_t rng, botan_mp_t lower_bound, botan_mp_t upper_bound);

BOTAN_FFI_EXPORT(2, 1) int botan_mp_gcd(botan_mp_t out, botan_mp_t x, botan_mp_t y);

/**
* Returns 0 if n is not prime
* Returns 1 if n is prime
* Returns negative number on error
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_is_prime(botan_mp_t n, botan_rng_t rng, size_t test_prob);

/**
* Returns 0 if specified bit of n is not set
* Returns 1 if specified bit of n is set
* Returns negative number on error
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_get_bit(botan_mp_t n, size_t bit);

/**
* Set the specified bit
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_set_bit(botan_mp_t n, size_t bit);

/**
* Clear the specified bit
*/
BOTAN_FFI_EXPORT(2, 1) int botan_mp_clear_bit(botan_mp_t n, size_t bit);

/* Bcrypt password hashing */

/**
* Create a password hash using Bcrypt
* @param out buffer holding the password hash, should be of length 64 bytes
* @param out_len the desired output length in bytes
* @param password the password
* @param rng a random number generator
* @param work_factor how much work to do to slow down guessing attacks
* @param flags should be 0 in current API revision, all other uses are reserved
*       and return BOTAN_FFI_ERROR_BAD_FLAG
* @return 0 on success, a negative value on failure

* Output is formatted bcrypt $2a$...
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_bcrypt_generate(
   uint8_t* out, size_t* out_len, const char* password, botan_rng_t rng, size_t work_factor, uint32_t flags);

/**
* Check a previously created password hash
* @param pass the password to check against
* @param hash the stored hash to check against
* @return 0 if if this password/hash combination is valid,
*       1 if the combination is not valid (but otherwise well formed),
*       negative on error
*/
BOTAN_FFI_EXPORT(2, 0) int botan_bcrypt_is_valid(const char* pass, const char* hash);

/*
* Public/private key creation, import, ...
*/
typedef struct botan_privkey_struct* botan_privkey_t;

/**
* Create a new private key
* @param key the new object will be placed here
* @param algo_name something like "RSA" or "ECDSA"
* @param algo_params is specific to the algorithm. For RSA, specifies
*        the modulus bit length. For ECC is the name of the curve.
* @param rng a random number generator
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_privkey_create(botan_privkey_t* key, const char* algo_name, const char* algo_params, botan_rng_t rng);

#define BOTAN_CHECK_KEY_EXPENSIVE_TESTS 1

BOTAN_FFI_EXPORT(2, 0) int botan_privkey_check_key(botan_privkey_t key, botan_rng_t rng, uint32_t flags);

BOTAN_FFI_DEPRECATED("Use botan_privkey_create")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_create_rsa(botan_privkey_t* key, botan_rng_t rng, size_t n_bits);
BOTAN_FFI_DEPRECATED("Use botan_privkey_create")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_create_ecdsa(botan_privkey_t* key, botan_rng_t rng, const char* params);
BOTAN_FFI_DEPRECATED("Use botan_privkey_create")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_create_ecdh(botan_privkey_t* key, botan_rng_t rng, const char* params);
BOTAN_FFI_DEPRECATED("Use botan_privkey_create")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_create_mceliece(botan_privkey_t* key, botan_rng_t rng, size_t n, size_t t);
BOTAN_FFI_DEPRECATED("Use botan_privkey_create")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_create_dh(botan_privkey_t* key, botan_rng_t rng, const char* param);

/**
 * Generates DSA key pair. Gives to a caller control over key length
 * and order of a subgroup 'q'.
 *
 * @param   key   handler to the resulting key
 * @param   rng   initialized PRNG
 * @param   pbits length of the key in bits. Must be between in range (1024, 3072)
 *          and multiple of 64. Bit size of the prime 'p'
 * @param   qbits order of the subgroup. Must be in range (160, 256) and multiple
 *          of 8
 *
 * @returns BOTAN_FFI_SUCCESS Success, `key' initialized with DSA key
 * @returns BOTAN_FFI_ERROR_NULL_POINTER  either `key' or `rng' is NULL
 * @returns BOTAN_FFI_ERROR_BAD_PARAMETER unexpected value for either `pbits' or
 *          `qbits'
 * @returns BOTAN_FFI_ERROR_NOT_IMPLEMENTED functionality not implemented
 *
*/
BOTAN_FFI_EXPORT(2, 5) int botan_privkey_create_dsa(botan_privkey_t* key, botan_rng_t rng, size_t pbits, size_t qbits);

/**
 * Generates ElGamal key pair. Caller has a control over key length
 * and order of a subgroup 'q'. Function is able to use two types of
 * primes:
 *    * if pbits-1 == qbits then safe primes are used for key generation
 *    * otherwise generation uses group of prime order
 *
 * @param   key   handler to the resulting key
 * @param   rng   initialized PRNG
 * @param   pbits length of the key in bits. Must be at least 1024
 * @param   qbits order of the subgroup. Must be at least 160
 *
 * @returns BOTAN_FFI_SUCCESS Success, `key' initialized with DSA key
 * @returns BOTAN_FFI_ERROR_NULL_POINTER  either `key' or `rng' is NULL
 * @returns BOTAN_FFI_ERROR_BAD_PARAMETER unexpected value for either `pbits' or
 *          `qbits'
 * @returns BOTAN_FFI_ERROR_NOT_IMPLEMENTED functionality not implemented
 *
*/
BOTAN_FFI_EXPORT(2, 5)
int botan_privkey_create_elgamal(botan_privkey_t* key, botan_rng_t rng, size_t pbits, size_t qbits);

/**
* Input currently assumed to be PKCS #8 structure;
* Set password to NULL to indicate no encryption expected
* Starting in 2.8.0, the rng parameter is unused and may be set to null
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_privkey_load(botan_privkey_t* key, botan_rng_t rng, const uint8_t bits[], size_t len, const char* password);

/**
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_destroy(botan_privkey_t key);

#define BOTAN_PRIVKEY_EXPORT_FLAG_DER 0
#define BOTAN_PRIVKEY_EXPORT_FLAG_PEM 1

/**
* On input *out_len is number of bytes in out[]
* On output *out_len is number of bytes written (or required)
* If out is not big enough no output is written, *out_len is set and 1 is returned
* Returns 0 on success and sets
* If some other error occurs a negative integer is returned.
*/
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_export(botan_privkey_t key, uint8_t out[], size_t* out_len, uint32_t flags);

/**
* View the private key's DER encoding
*/
BOTAN_FFI_EXPORT(3, 0) int botan_privkey_view_der(botan_privkey_t key, botan_view_ctx ctx, botan_view_bin_fn view);

/**
* View the private key's PEM encoding
*/
BOTAN_FFI_EXPORT(3, 0) int botan_privkey_view_pem(botan_privkey_t key, botan_view_ctx ctx, botan_view_str_fn view);

BOTAN_FFI_EXPORT(2, 8) int botan_privkey_algo_name(botan_privkey_t key, char out[], size_t* out_len);

/**
* Set encryption_algo to NULL or "" to have the library choose a default (recommended)
*/
BOTAN_FFI_DEPRECATED("Use botan_privkey_export_encrypted_pbkdf_{msec,iter}")
BOTAN_FFI_EXPORT(2, 0)
int botan_privkey_export_encrypted(botan_privkey_t key,
                                   uint8_t out[],
                                   size_t* out_len,
                                   botan_rng_t rng,
                                   const char* passphrase,
                                   const char* encryption_algo,
                                   uint32_t flags);

/*
* Export a private key, running PBKDF for specified amount of time
* @param key the private key to export
*
* Note: starting in 3.0, the output iterations count is not provided
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_privkey_export_encrypted_pbkdf_msec(botan_privkey_t key,
                                              uint8_t out[],
                                              size_t* out_len,
                                              botan_rng_t rng,
                                              const char* passphrase,
                                              uint32_t pbkdf_msec_runtime,
                                              size_t* pbkdf_iterations_out,
                                              const char* cipher_algo,
                                              const char* pbkdf_algo,
                                              uint32_t flags);

/**
* Export a private key using the specified number of iterations.
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_privkey_export_encrypted_pbkdf_iter(botan_privkey_t key,
                                              uint8_t out[],
                                              size_t* out_len,
                                              botan_rng_t rng,
                                              const char* passphrase,
                                              size_t pbkdf_iterations,
                                              const char* cipher_algo,
                                              const char* pbkdf_algo,
                                              uint32_t flags);

/**
* View the encryption of a private key (binary DER encoding)
*
* Set cipher_algo, pbkdf_algo to NULL to use defaults
* Set pbkdf_iterations to 0 to use defaults
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_privkey_view_encrypted_der(botan_privkey_t key,
                                     botan_rng_t rng,
                                     const char* passphrase,
                                     const char* cipher_algo,
                                     const char* pbkdf_algo,
                                     size_t pbkdf_iterations,
                                     botan_view_ctx ctx,
                                     botan_view_bin_fn view);

/**
* View the encryption of a private key (binary DER encoding)
*
* Set cipher_algo, pbkdf_algo to NULL to use defaults
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_privkey_view_encrypted_der_timed(botan_privkey_t key,
                                           botan_rng_t rng,
                                           const char* passphrase,
                                           const char* cipher_algo,
                                           const char* pbkdf_algo,
                                           size_t pbkdf_runtime_msec,
                                           botan_view_ctx ctx,
                                           botan_view_bin_fn view);

/**
* View the encryption of a private key (PEM encoding)
*
* Set cipher_algo, pbkdf_algo to NULL to use defaults
* Set pbkdf_iterations to 0 to use defaults
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_privkey_view_encrypted_pem(botan_privkey_t key,
                                     botan_rng_t rng,
                                     const char* passphrase,
                                     const char* cipher_algo,
                                     const char* pbkdf_algo,
                                     size_t pbkdf_iterations,
                                     botan_view_ctx ctx,
                                     botan_view_str_fn view);

/**
* View the encryption of a private key (PEM encoding)
*
* Set cipher_algo, pbkdf_algo to NULL to use defaults
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_privkey_view_encrypted_pem_timed(botan_privkey_t key,
                                           botan_rng_t rng,
                                           const char* passphrase,
                                           const char* cipher_algo,
                                           const char* pbkdf_algo,
                                           size_t pbkdf_runtime_msec,
                                           botan_view_ctx ctx,
                                           botan_view_str_fn view);

typedef struct botan_pubkey_struct* botan_pubkey_t;

BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_load(botan_pubkey_t* key, const uint8_t bits[], size_t len);

BOTAN_FFI_EXPORT(2, 0) int botan_privkey_export_pubkey(botan_pubkey_t* out, botan_privkey_t in);

BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_export(botan_pubkey_t key, uint8_t out[], size_t* out_len, uint32_t flags);

/**
* View the public key's DER encoding
*/
BOTAN_FFI_EXPORT(3, 0) int botan_pubkey_view_der(botan_pubkey_t key, botan_view_ctx ctx, botan_view_bin_fn view);

/**
* View the public key's PEM encoding
*/
BOTAN_FFI_EXPORT(3, 0) int botan_pubkey_view_pem(botan_pubkey_t key, botan_view_ctx ctx, botan_view_str_fn view);

BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_algo_name(botan_pubkey_t key, char out[], size_t* out_len);

/**
* Returns 0 if key is valid, negative if invalid key or some other error
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_check_key(botan_pubkey_t key, botan_rng_t rng, uint32_t flags);

BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_estimated_strength(botan_pubkey_t key, size_t* estimate);

BOTAN_FFI_EXPORT(2, 0)
int botan_pubkey_fingerprint(botan_pubkey_t key, const char* hash, uint8_t out[], size_t* out_len);

/**
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_destroy(botan_pubkey_t key);

/*
* Get arbitrary named fields from public or private keys
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_get_field(botan_mp_t output, botan_pubkey_t key, const char* field_name);

BOTAN_FFI_EXPORT(2, 0) int botan_privkey_get_field(botan_mp_t output, botan_privkey_t key, const char* field_name);

/*
* Algorithm specific key operations: RSA
*/
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_load_rsa(botan_privkey_t* key, botan_mp_t p, botan_mp_t q, botan_mp_t e);

BOTAN_FFI_EXPORT(2, 8) int botan_privkey_load_rsa_pkcs1(botan_privkey_t* key, const uint8_t bits[], size_t len);

BOTAN_FFI_DEPRECATED("Use botan_privkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_rsa_get_p(botan_mp_t p, botan_privkey_t rsa_key);
BOTAN_FFI_DEPRECATED("Use botan_privkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_rsa_get_q(botan_mp_t q, botan_privkey_t rsa_key);
BOTAN_FFI_DEPRECATED("Use botan_privkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_rsa_get_d(botan_mp_t d, botan_privkey_t rsa_key);
BOTAN_FFI_DEPRECATED("Use botan_privkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_rsa_get_n(botan_mp_t n, botan_privkey_t rsa_key);
BOTAN_FFI_DEPRECATED("Use botan_privkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_rsa_get_e(botan_mp_t e, botan_privkey_t rsa_key);

BOTAN_FFI_EXPORT(2, 8)
int botan_privkey_rsa_get_privkey(botan_privkey_t rsa_key, uint8_t out[], size_t* out_len, uint32_t flags);

BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_load_rsa(botan_pubkey_t* key, botan_mp_t n, botan_mp_t e);

BOTAN_FFI_DEPRECATED("Use botan_pubkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_rsa_get_e(botan_mp_t e, botan_pubkey_t rsa_key);
BOTAN_FFI_DEPRECATED("Use botan_pubkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_rsa_get_n(botan_mp_t n, botan_pubkey_t rsa_key);

/*
* Algorithm specific key operations: DSA
*/
BOTAN_FFI_EXPORT(2, 0)
int botan_privkey_load_dsa(botan_privkey_t* key, botan_mp_t p, botan_mp_t q, botan_mp_t g, botan_mp_t x);

BOTAN_FFI_EXPORT(2, 0)
int botan_pubkey_load_dsa(botan_pubkey_t* key, botan_mp_t p, botan_mp_t q, botan_mp_t g, botan_mp_t y);

BOTAN_FFI_DEPRECATED("Use botan_privkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_dsa_get_x(botan_mp_t n, botan_privkey_t key);

BOTAN_FFI_DEPRECATED("Use botan_pubkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_dsa_get_p(botan_mp_t p, botan_pubkey_t key);
BOTAN_FFI_DEPRECATED("Use botan_pubkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_dsa_get_q(botan_mp_t q, botan_pubkey_t key);
BOTAN_FFI_DEPRECATED("Use botan_pubkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_dsa_get_g(botan_mp_t d, botan_pubkey_t key);
BOTAN_FFI_DEPRECATED("Use botan_pubkey_get_field")
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_dsa_get_y(botan_mp_t y, botan_pubkey_t key);

/*
* Loads Diffie Hellman private key
*
* @param key variable populated with key material
* @param p prime order of a Z_p group
* @param g group generator
* @param x private key
*
* @pre key is NULL on input
* @post function allocates memory and assigns to `key'
*
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_load_dh(botan_privkey_t* key, botan_mp_t p, botan_mp_t g, botan_mp_t x);
/**
* Loads Diffie Hellman public key
*
* @param key variable populated with key material
* @param p prime order of a Z_p group
* @param g group generator
* @param y public key
*
* @pre key is NULL on input
* @post function allocates memory and assigns to `key'
*
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_load_dh(botan_pubkey_t* key, botan_mp_t p, botan_mp_t g, botan_mp_t y);

/*
* Algorithm specific key operations: ElGamal
*/

/**
* Loads ElGamal public key
* @param key variable populated with key material
* @param p prime order of a Z_p group
* @param g group generator
* @param y public key
*
* @pre key is NULL on input
* @post function allocates memory and assigns to `key'
*
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pubkey_load_elgamal(botan_pubkey_t* key, botan_mp_t p, botan_mp_t g, botan_mp_t y);

/**
* Loads ElGamal private key
*
* @param key variable populated with key material
* @param p prime order of a Z_p group
* @param g group generator
* @param x private key
*
* @pre key is NULL on input
* @post function allocates memory and assigns to `key'
*
* @return 0 on success, a negative value on failure
*/
BOTAN_FFI_EXPORT(2, 0) int botan_privkey_load_elgamal(botan_privkey_t* key, botan_mp_t p, botan_mp_t g, botan_mp_t x);

/*
* Algorithm specific key operations: Ed25519
*/

BOTAN_FFI_EXPORT(2, 2) int botan_privkey_load_ed25519(botan_privkey_t* key, const uint8_t privkey[32]);

BOTAN_FFI_EXPORT(2, 2) int botan_pubkey_load_ed25519(botan_pubkey_t* key, const uint8_t pubkey[32]);

BOTAN_FFI_EXPORT(2, 2) int botan_privkey_ed25519_get_privkey(botan_privkey_t key, uint8_t output[64]);

BOTAN_FFI_EXPORT(2, 2) int botan_pubkey_ed25519_get_pubkey(botan_pubkey_t key, uint8_t pubkey[32]);

/*
* Algorithm specific key operations: X25519
*/

BOTAN_FFI_EXPORT(2, 8) int botan_privkey_load_x25519(botan_privkey_t* key, const uint8_t privkey[32]);

BOTAN_FFI_EXPORT(2, 8) int botan_pubkey_load_x25519(botan_pubkey_t* key, const uint8_t pubkey[32]);

BOTAN_FFI_EXPORT(2, 8) int botan_privkey_x25519_get_privkey(botan_privkey_t key, uint8_t output[32]);

BOTAN_FFI_EXPORT(2, 8) int botan_pubkey_x25519_get_pubkey(botan_pubkey_t key, uint8_t pubkey[32]);

/*
* Algorithm specific key operations: Kyber
*/

BOTAN_FFI_EXPORT(3, 1) int botan_privkey_load_kyber(botan_privkey_t* key, const uint8_t privkey[], size_t key_len);

BOTAN_FFI_EXPORT(3, 1) int botan_pubkey_load_kyber(botan_pubkey_t* key, const uint8_t pubkey[], size_t key_len);

BOTAN_FFI_EXPORT(3, 1)
int botan_privkey_view_kyber_raw_key(botan_privkey_t key, botan_view_ctx ctx, botan_view_bin_fn view);

BOTAN_FFI_EXPORT(3, 1)
int botan_pubkey_view_kyber_raw_key(botan_pubkey_t key, botan_view_ctx ctx, botan_view_bin_fn view);

/*
* Algorithm specific key operations: ECDSA and ECDH
*/
BOTAN_FFI_EXPORT(3, 2)
int botan_pubkey_ecc_key_used_explicit_encoding(botan_pubkey_t key);

BOTAN_FFI_EXPORT(2, 2)
int botan_privkey_load_ecdsa(botan_privkey_t* key, botan_mp_t scalar, const char* curve_name);

BOTAN_FFI_EXPORT(2, 2)
int botan_pubkey_load_ecdsa(botan_pubkey_t* key, botan_mp_t public_x, botan_mp_t public_y, const char* curve_name);

BOTAN_FFI_EXPORT(2, 2)
int botan_pubkey_load_ecdh(botan_pubkey_t* key, botan_mp_t public_x, botan_mp_t public_y, const char* curve_name);

BOTAN_FFI_EXPORT(2, 2)
int botan_privkey_load_ecdh(botan_privkey_t* key, botan_mp_t scalar, const char* curve_name);

BOTAN_FFI_EXPORT(2, 2)
int botan_pubkey_load_sm2(botan_pubkey_t* key, botan_mp_t public_x, botan_mp_t public_y, const char* curve_name);

BOTAN_FFI_EXPORT(2, 2)
int botan_privkey_load_sm2(botan_privkey_t* key, botan_mp_t scalar, const char* curve_name);

BOTAN_FFI_DEPRECATED("Use botan_pubkey_load_sm2")
BOTAN_FFI_EXPORT(2, 2)
int botan_pubkey_load_sm2_enc(botan_pubkey_t* key, botan_mp_t public_x, botan_mp_t public_y, const char* curve_name);

BOTAN_FFI_DEPRECATED("Use botan_privkey_load_sm2")
BOTAN_FFI_EXPORT(2, 2)
int botan_privkey_load_sm2_enc(botan_privkey_t* key, botan_mp_t scalar, const char* curve_name);

BOTAN_FFI_EXPORT(2, 3)
int botan_pubkey_sm2_compute_za(
   uint8_t out[], size_t* out_len, const char* ident, const char* hash_algo, botan_pubkey_t key);

/**
* View the uncompressed public point associated with the key
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_pubkey_view_ec_public_point(botan_pubkey_t key, botan_view_ctx ctx, botan_view_bin_fn view);

/*
* Public Key Encryption
*/
typedef struct botan_pk_op_encrypt_struct* botan_pk_op_encrypt_t;

BOTAN_FFI_EXPORT(2, 0)
int botan_pk_op_encrypt_create(botan_pk_op_encrypt_t* op, botan_pubkey_t key, const char* padding, uint32_t flags);

/**
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pk_op_encrypt_destroy(botan_pk_op_encrypt_t op);

BOTAN_FFI_EXPORT(2, 8)
int botan_pk_op_encrypt_output_length(botan_pk_op_encrypt_t op, size_t ptext_len, size_t* ctext_len);

BOTAN_FFI_EXPORT(2, 0)
int botan_pk_op_encrypt(botan_pk_op_encrypt_t op,
                        botan_rng_t rng,
                        uint8_t out[],
                        size_t* out_len,
                        const uint8_t plaintext[],
                        size_t plaintext_len);

/*
* Public Key Decryption
*/
typedef struct botan_pk_op_decrypt_struct* botan_pk_op_decrypt_t;

BOTAN_FFI_EXPORT(2, 0)
int botan_pk_op_decrypt_create(botan_pk_op_decrypt_t* op, botan_privkey_t key, const char* padding, uint32_t flags);

/**
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pk_op_decrypt_destroy(botan_pk_op_decrypt_t op);

BOTAN_FFI_EXPORT(2, 8)
int botan_pk_op_decrypt_output_length(botan_pk_op_decrypt_t op, size_t ctext_len, size_t* ptext_len);

BOTAN_FFI_EXPORT(2, 0)
int botan_pk_op_decrypt(
   botan_pk_op_decrypt_t op, uint8_t out[], size_t* out_len, const uint8_t ciphertext[], size_t ciphertext_len);

/*
* Signature Generation
*/

#define BOTAN_PUBKEY_DER_FORMAT_SIGNATURE 1

typedef struct botan_pk_op_sign_struct* botan_pk_op_sign_t;

BOTAN_FFI_EXPORT(2, 0)
int botan_pk_op_sign_create(botan_pk_op_sign_t* op, botan_privkey_t key, const char* hash_and_padding, uint32_t flags);

/**
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pk_op_sign_destroy(botan_pk_op_sign_t op);

BOTAN_FFI_EXPORT(2, 8) int botan_pk_op_sign_output_length(botan_pk_op_sign_t op, size_t* olen);

BOTAN_FFI_EXPORT(2, 0) int botan_pk_op_sign_update(botan_pk_op_sign_t op, const uint8_t in[], size_t in_len);

BOTAN_FFI_EXPORT(2, 0)
int botan_pk_op_sign_finish(botan_pk_op_sign_t op, botan_rng_t rng, uint8_t sig[], size_t* sig_len);

/*
* Signature Verification
*/
typedef struct botan_pk_op_verify_struct* botan_pk_op_verify_t;

BOTAN_FFI_EXPORT(2, 0)
int botan_pk_op_verify_create(botan_pk_op_verify_t* op,
                              botan_pubkey_t key,
                              const char* hash_and_padding,
                              uint32_t flags);

/**
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pk_op_verify_destroy(botan_pk_op_verify_t op);

BOTAN_FFI_EXPORT(2, 0) int botan_pk_op_verify_update(botan_pk_op_verify_t op, const uint8_t in[], size_t in_len);
BOTAN_FFI_EXPORT(2, 0) int botan_pk_op_verify_finish(botan_pk_op_verify_t op, const uint8_t sig[], size_t sig_len);

/*
* Key Agreement
*/
typedef struct botan_pk_op_ka_struct* botan_pk_op_ka_t;

BOTAN_FFI_EXPORT(2, 0)
int botan_pk_op_key_agreement_create(botan_pk_op_ka_t* op, botan_privkey_t key, const char* kdf, uint32_t flags);

/**
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_pk_op_key_agreement_destroy(botan_pk_op_ka_t op);

BOTAN_FFI_EXPORT(2, 0) int botan_pk_op_key_agreement_export_public(botan_privkey_t key, uint8_t out[], size_t* out_len);

BOTAN_FFI_EXPORT(3, 0)
int botan_pk_op_key_agreement_view_public(botan_privkey_t key, botan_view_ctx ctx, botan_view_bin_fn view);

BOTAN_FFI_EXPORT(2, 8) int botan_pk_op_key_agreement_size(botan_pk_op_ka_t op, size_t* out_len);

BOTAN_FFI_EXPORT(2, 0)
int botan_pk_op_key_agreement(botan_pk_op_ka_t op,
                              uint8_t out[],
                              size_t* out_len,
                              const uint8_t other_key[],
                              size_t other_key_len,
                              const uint8_t salt[],
                              size_t salt_len);

/*
* Key Encapsulation
*/
typedef struct botan_pk_op_kem_encrypt_struct* botan_pk_op_kem_encrypt_t;

BOTAN_FFI_EXPORT(3, 0)
int botan_pk_op_kem_encrypt_create(botan_pk_op_kem_encrypt_t* op, botan_pubkey_t key, const char* kdf);

/**
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(3, 0) int botan_pk_op_kem_encrypt_destroy(botan_pk_op_kem_encrypt_t op);

BOTAN_FFI_EXPORT(3, 0)
int botan_pk_op_kem_encrypt_shared_key_length(botan_pk_op_kem_encrypt_t op,
                                              size_t desired_shared_key_length,
                                              size_t* output_shared_key_length);

BOTAN_FFI_EXPORT(3, 0)
int botan_pk_op_kem_encrypt_encapsulated_key_length(botan_pk_op_kem_encrypt_t op,
                                                    size_t* output_encapsulated_key_length);

BOTAN_FFI_EXPORT(3, 0)
int botan_pk_op_kem_encrypt_create_shared_key(botan_pk_op_kem_encrypt_t op,
                                              botan_rng_t rng,
                                              const uint8_t salt[],
                                              size_t salt_len,
                                              size_t desired_shared_key_len,
                                              uint8_t shared_key[],
                                              size_t* shared_key_len,
                                              uint8_t encapsulated_key[],
                                              size_t* encapsulated_key_len);

typedef struct botan_pk_op_kem_decrypt_struct* botan_pk_op_kem_decrypt_t;

BOTAN_FFI_EXPORT(3, 0)
int botan_pk_op_kem_decrypt_create(botan_pk_op_kem_decrypt_t* op, botan_privkey_t key, const char* kdf);

/**
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(3, 0) int botan_pk_op_kem_decrypt_destroy(botan_pk_op_kem_decrypt_t op);

BOTAN_FFI_EXPORT(3, 0)
int botan_pk_op_kem_decrypt_shared_key_length(botan_pk_op_kem_decrypt_t op,
                                              size_t desired_shared_key_length,
                                              size_t* output_shared_key_length);

BOTAN_FFI_EXPORT(3, 0)
int botan_pk_op_kem_decrypt_shared_key(botan_pk_op_kem_decrypt_t op,
                                       const uint8_t salt[],
                                       size_t salt_len,
                                       const uint8_t encapsulated_key[],
                                       size_t encapsulated_key_len,
                                       size_t desired_shared_key_len,
                                       uint8_t shared_key[],
                                       size_t* shared_key_len);

/**
* Signature Scheme Utility Functions
*/

BOTAN_FFI_EXPORT(2, 0) int botan_pkcs_hash_id(const char* hash_name, uint8_t pkcs_id[], size_t* pkcs_id_len);

/*
* Always returns BOTAN_FFI_ERROR_NOT_IMPLEMENTED
*/
BOTAN_FFI_DEPRECATED("No longer implemented")
BOTAN_FFI_EXPORT(2, 0)
int botan_mceies_encrypt(botan_pubkey_t mce_key,
                         botan_rng_t rng,
                         const char* aead,
                         const uint8_t pt[],
                         size_t pt_len,
                         const uint8_t ad[],
                         size_t ad_len,
                         uint8_t ct[],
                         size_t* ct_len);

/*
* Always returns BOTAN_FFI_ERROR_NOT_IMPLEMENTED
*/
BOTAN_FFI_DEPRECATED("No longer implemented")
BOTAN_FFI_EXPORT(2, 0)
int botan_mceies_decrypt(botan_privkey_t mce_key,
                         const char* aead,
                         const uint8_t ct[],
                         size_t ct_len,
                         const uint8_t ad[],
                         size_t ad_len,
                         uint8_t pt[],
                         size_t* pt_len);

/*
* X.509 general
**************************/

// NOTE: I totally borked the naming convention for _obj. I should be calling
// things _ptr and not _obj to disambiguate, and then make consistent.
// TODO: Consistent initializers - look at botan_x509_cert_options_create vs botan_x509_ca_create_padding
// Aside from the _obj thing, there's also the questions of:
// - The initial '*foo = nullptr;'
// - Whether we need this check:
/*    
if(foo_obj) {
   *foo = new botan_x509_foo_struct(std::move(foo_obj));
   return BOTAN_FFI_SUCCESS;
}
return BOTAN_FFI_ERROR_UNKNOWN_ERROR;
*/

// WARNING: Several functions return arrays of things:
// DN functions return arrays of distinguished name values, key-value pairs
// Store functions return arrays of certs
// We need to make a consistent method of allocating / transferring ownership 

// TODO: Returning bytestrings, discuss:
//    uint8_t out[], size_t* out_len,
// vs
//    uint8_t* out, size_t* out_len
// Different authors have preferred either, I forget at this moment
// whether it matters.

// TODO: Implement explicit PEM and  BER / DER encoding / decoding
// Eg, X509 Certs have to_string, but not PEM_encode or BER_encode
//
// BOTAN_FFI_EXPORT(3,3)
// int botan_x509_foo_encode_pem(
//    uint8_t out[], size_t* out_len,
//    botan_x509_foo_t foo);
//
// BOTAN_FFI_EXPORT(3,3)
// int botan_x509_foo_encode_der(
//    uint8_t out[], size_t* out_len,
//    botan_x509_foo_t foo);

// TODO: X509_Usage_Type
/*

enum class Usage_Type {
   UNSPECIFIED,  // no restrictions
   TLS_SERVER_AUTH,
   TLS_CLIENT_AUTH,
   CERTIFICATE_AUTHORITY,
   OCSP_RESPONDER,
   ENCRYPTION
};
*/
// SEE: cert allowed_usage, x509_path_validate

// NOTE: I'm fairly certain that I'm not properly transferring ownership
// of things involving strings and arrays.
// For instance, I am not using write_str_output or anything like that.

// NOTE: Many portions of  the X509 spec have been ignored / elided in
// in the FFI in various ways - in particular:
//    Distinguished Names by encoded strings and invidual attribute lookup
//    Extensions by the Options struct
//    Path Validation by botan_x509_cert_verify_with_crl (which is just a wrapper
//       around x509_path_validate)
// This suffices in limiting the API surface for the read-only purposes
// of the extant X509 FFI, but do not necessarily suffice for the purposes of
// read-write-create that the extended FFI needs
// It was difficult to tell up-front what these needs were, and so some code
// has been written that is now obviated, at least for the moment.
// This is fine for now; we can create Certificate Authorities, Revocation Lists,
// Stores, and Signing Requests to sign new Certificates, which is a nice chunk of
// new FFI functionality. Given more time, we could make it more complete and
// consistent, but that would require more changes to the existing API.

/*
* X.509 distinguished names
**************************/

// NOTE: I do not know if Botan supports multi-valued X509_DN,
// and will not assume so until I perform the required research.
// NOTE: The FFI has no OID type, and I will not implement one at this time.
// I will just use encoded string functions.

// NOTE: For multimap<string,string> FFI output :
//    uint8_t** keys, size_t* key_sizes,
//    uint8_t** vals, size_t* val_sizes,
//    size_t* count
// For input? - need to have a proper discussion on this:
//    const uint8_t keys[][], size_t key_lens[],
//    const uint8_t vals[][], size_t val_lens[],
//    size_t count
// NO doesnt work; trying:
//    const uint8_t* keys[], const size_t key_lens[],
//    const uint8_t* vals[], const size_t val_lens[],
//    size_t count

typedef struct botan_x509_dn_struct* botan_x509_dn_t;

BOTAN_FFI_EXPORT(3,3)
int botan_x509_dn_destroy(botan_x509_dn_t dn);

// TODO: Add / update various DN encoded-string functions
//    uint8_t dn[], size_t* dn_len
// with DN objects
//    botan_x509_dn_t* dn
// For now, just construct a DN, encode it, and pass
// to the DN encoded-string functions.

BOTAN_FFI_EXPORT(3,3)
int botan_x509_dn_create(botan_x509_dn_t* dn);

// TODO: Better name? botan_x509_dn_load?
// TODO: Improve upon? See discussion of multimap input / output
BOTAN_FFI_EXPORT(3,3)
int botan_x509_dn_create_from_multimap(
   botan_x509_dn_t* dn,
   const uint8_t* keys[], const size_t key_lens[],
   const uint8_t* vals[], const size_t val_lens[],
   size_t count
   );

BOTAN_FFI_EXPORT(3,3)
int botan_x509_dn_to_string(
   uint8_t out[], size_t* out_len,
   botan_x509_dn_t dn);

// TODO: Implement BER / DER encoding?

// TODO: Better interface than this

// NOTE: Returns boolean success code
BOTAN_FFI_EXPORT(3,3)
int botan_x509_dn_has_field(
   botan_x509_dn_t dn,
   const uint8_t key[], size_t key_len);
   
BOTAN_FFI_EXPORT(3,3)
int botan_x509_dn_get_first_attribute(
   uint8_t out[], size_t* out_len,
   botan_x509_dn_t dn,
   const uint8_t key[], size_t key_len);

// TODO: vals, sizes, count
BOTAN_FFI_EXPORT(3,3)
int botan_x509_dn_get_attribute(
   uint8_t** vals, size_t* val_sizes, size_t* val_count,
   botan_x509_dn_t dn,
   const uint8_t key[], size_t key_len);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_dn_contents(
   uint8_t** keys, size_t* key_sizes, uint8_t** vals, size_t* val_sizes, size_t* count,
   botan_x509_dn_t dn);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_dn_add_attribute(
   botan_x509_dn_t dn,
   const uint8_t key[], size_t key_len,
   const uint8_t val[], size_t val_len);

/*
* X.509 Certificate Extensions
**************************/

// TODO: Probably use extn instead of ext
// TODO: Singular extension vs extensions object...
typedef struct botan_x509_cert_ext_struct* botan_x509_cert_ext_t;
// TODO: Rename this ^ or that v for consistency
typedef struct botan_x509_exts_struct* botan_x509_exts_t;
// There will probably be issues with allocating and free'ing
// individual extension structs vs the extensions struct
// unless we transfer ownership to the exts object and automatically
// destroy child extension objects when the extensions object is
// destroyed.

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_destroy(botan_x509_cert_ext_t exts);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_exts_destroy(botan_x509_exts_t exts);

// NOTE: Ownership of objects is finnicky across the C FFI barrier, especially
// with nested objects
// TODO: Determine whether we should bother with individual extension objects:
//*

// Extensions functions

BOTAN_FFI_EXPORT(3,3)
int botan_x509_exts_add(
   botan_x509_exts_t exts,
   botan_x509_cert_ext_t ext,
   bool critical);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_exts_add_new(
   botan_x509_exts_t exts,
   botan_x509_cert_ext_t ext,
   bool critical);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_exts_replace(
   botan_x509_exts_t exts,
   botan_x509_cert_ext_t ext,
   bool critical);

// NOTE: Remove takes an OID
BOTAN_FFI_EXPORT(3,3)
int botan_x509_exts_remove(
   botan_x509_exts_t exts,
   const uint8_t oid[], size_t oid_len);

// Individual extension functions

// Basic_Constraints
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_basic_constraints(
   botan_x509_cert_ext_t* ext,
   bool ca,
   int path_limit);

// Key_Usage
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_key_usage(
   botan_x509_cert_ext_t* ext,
   unsigned int key_usage);

// Subject_Key_ID
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_subject_key_id(
   botan_x509_cert_ext_t* ext,
   botan_pubkey_t pubkey,
   const char* hash_fn);

// Authority_Key_ID
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_authority_key_id(
   botan_x509_cert_ext_t* ext);

// Subject_Alternative_Name
// NOTE: From documentation:
//    Subject Alternative Names: Only the “rfc822Name”, “dNSName”, and “uniformResourceIdentifier”
//    and raw IPv4 fields will be stored; all others are ignored.
// This means email, dns, uri, and ip
// We will avoid constructing an AlternativeName object
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_subject_alternative_name(
   botan_x509_cert_ext_t* ext,
   const uint8_t email[], size_t email_len,
   const uint8_t dns[], size_t dns_len,
   const uint8_t uri[], size_t uri_len,
   const uint8_t ip[], size_t ip_len);

// Issuer_Alternative_Name
// DITTO
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_issuer_alternative_name(
   botan_x509_cert_ext_t* ext,
   const uint8_t email[], size_t email_len,
   const uint8_t dns[], size_t dns_len,
   const uint8_t uri[], size_t uri_len,
   const uint8_t ip[], size_t ip_len);

//Extended_Key_Usage
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_extended_key_usage(
   botan_x509_cert_ext_t* ext,
   const uint8_t* oid[], size_t oid_len[],size_t oid_count);

// Name_Constraint
// NOTE: This relies on NameConstraint (not Name_Costraint!) which depends on
// GeneralSubtree and then GeneralName
// NOTE: It also does not support encoding:
//    Name Constraints: No problems known (though encoding is not supported).
// So it is probably only logical to support string constructor
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_name_constraint(
   botan_x509_cert_ext_t* ext,
   const uint8_t name_constraint[], size_t name_constraint_len);

// Certificate_Policies
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_certificate_policies(
   botan_x509_cert_ext_t* ext,
   const uint8_t* oid[], size_t oid_len[],size_t oid_count);

// Authority_Information_Access
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_authority_information_access(
   botan_x509_cert_ext_t* ext,
   const uint8_t ocsp[], size_t ocsp_len,
   const uint8_t* ca_issuers[], size_t ca_issuers_len[], size_t ca_issuers_count);

// CRL_Number
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_crl_number(
   botan_x509_cert_ext_t* ext);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_crl_number_from_number(
   botan_x509_cert_ext_t* ext,
   size_t crl_number);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_crl_number_get_number(
   size_t* crl_number,
   botan_x509_cert_ext_t ext);

// CRL_ReasonCode
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_crl_reason_code(
   botan_x509_cert_ext_t* ext,
   uint32_t crl_reason_code);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_crl_reason_code_get_reason(
   uint32_t* crl_reason_code,
   botan_x509_cert_ext_t ext);

// CRL_Distribution_Points
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_crl_distribution_points(
   botan_x509_cert_ext_t* ext);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_crl_distribution_points_add_distribution_point(
   botan_x509_cert_ext_t* ext,
   const uint8_t email[], size_t email_len,
   const uint8_t dns[], size_t dns_len,
   const uint8_t uri[], size_t uri_len,
   const uint8_t ip[], size_t ip_len);

// CRL_Issuing_Distribution_Point
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_crl_issuing_distribution_points(
   botan_x509_cert_ext_t* ext);
   
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_crl_issuing_distribution_points_add_distribution_point(
   botan_x509_cert_ext_t* ext,
   const uint8_t email[], size_t email_len,
   const uint8_t dns[], size_t dns_len,
   const uint8_t uri[], size_t uri_len,
   const uint8_t ip[], size_t ip_len);

// OCSP_NoCheck
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_ocsp_nocheck(
   botan_x509_cert_ext_t* ext);

// Unknown_Extension
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_ext_unknown_extension(
   botan_x509_cert_ext_t* ext,
   const uint8_t oid[], size_t oid_len,
   bool critical);

// ...

//*/
// Or if we should just deal with the Extensions object:
/*

BOTAN_FFI_EXPORT(3,3)
int botan_x509_exts_add_basic_constraints(
   botan_x509_exts_t ext,
   bool ca,
   int path_limit,
   bool critical,
   bool replace);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_exts_key_usage(
   botan_x509_exts_t ext,
   unsigned int key_usage,
   bool critical,
   bool replace);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_exts_subject_key_id(
   botan_x509_exts_t ext,
   botan_pubkey_t pubkey,
   const char* hash_fn,
   bool critical,
   bool replace);

//*/

// TODO: Rest of the X509 Extensions, once a decision is made.


/*
* X.509 certificates
**************************/

typedef struct botan_x509_cert_struct* botan_x509_cert_t;

BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_load(botan_x509_cert_t* cert_obj, const uint8_t cert[], size_t cert_len);
BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_load_file(botan_x509_cert_t* cert_obj, const char* filename);

/**
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_destroy(botan_x509_cert_t cert);

BOTAN_FFI_EXPORT(2, 8) int botan_x509_cert_dup(botan_x509_cert_t* new_cert, botan_x509_cert_t cert);

/* Prefer botan_x509_cert_not_before and botan_x509_cert_not_after */
BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_get_time_starts(botan_x509_cert_t cert, char out[], size_t* out_len);
BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_get_time_expires(botan_x509_cert_t cert, char out[], size_t* out_len);

BOTAN_FFI_EXPORT(2, 8) int botan_x509_cert_not_before(botan_x509_cert_t cert, uint64_t* time_since_epoch);
BOTAN_FFI_EXPORT(2, 8) int botan_x509_cert_not_after(botan_x509_cert_t cert, uint64_t* time_since_epoch);

BOTAN_FFI_EXPORT(2, 0)
int botan_x509_cert_get_fingerprint(botan_x509_cert_t cert, const char* hash, uint8_t out[], size_t* out_len);

BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_get_serial_number(botan_x509_cert_t cert, uint8_t out[], size_t* out_len);
BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_get_authority_key_id(botan_x509_cert_t cert, uint8_t out[], size_t* out_len);
BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_get_subject_key_id(botan_x509_cert_t cert, uint8_t out[], size_t* out_len);

BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_get_public_key_bits(botan_x509_cert_t cert, uint8_t out[], size_t* out_len);

BOTAN_FFI_EXPORT(3, 0)
int botan_x509_cert_view_public_key_bits(botan_x509_cert_t cert, botan_view_ctx ctx, botan_view_bin_fn view);

BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_get_public_key(botan_x509_cert_t cert, botan_pubkey_t* key);

BOTAN_FFI_EXPORT(2, 0)
int botan_x509_cert_get_issuer_dn(
   botan_x509_cert_t cert, const char* key, size_t index, uint8_t out[], size_t* out_len);

// NOTE: Returns an actual DN object
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_issuer_dn(
   botan_x509_dn_t* dn,
   botan_x509_cert_t cert,
   const char* key,
   size_t index);

BOTAN_FFI_EXPORT(2, 0)
int botan_x509_cert_get_subject_dn(
   botan_x509_cert_t cert, const char* key, size_t index, uint8_t out[], size_t* out_len);

// NOTE: Returns an actual DN object
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_subject_dn(
   botan_x509_dn_t* dn,
   botan_x509_cert_t cert,
   const char* key,
   size_t index);

BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_to_string(botan_x509_cert_t cert, char out[], size_t* out_len);

BOTAN_FFI_EXPORT(3, 0)
int botan_x509_cert_view_as_string(botan_x509_cert_t cert, botan_view_ctx ctx, botan_view_str_fn view);

/* Must match values of Key_Constraints in key_constraints.h */
enum botan_x509_cert_key_constraints {
   NO_CONSTRAINTS = 0,
   DIGITAL_SIGNATURE = 32768,
   NON_REPUDIATION = 16384,
   KEY_ENCIPHERMENT = 8192,
   DATA_ENCIPHERMENT = 4096,
   KEY_AGREEMENT = 2048,
   KEY_CERT_SIGN = 1024,
   CRL_SIGN = 512,
   ENCIPHER_ONLY = 256,
   DECIPHER_ONLY = 128
};

BOTAN_FFI_EXPORT(2, 0) int botan_x509_cert_allowed_usage(botan_x509_cert_t cert, unsigned int key_usage);

/**
* Check if the certificate matches the specified hostname via alternative name or CN match.
* RFC 5280 wildcards also supported.
*/
BOTAN_FFI_EXPORT(2, 5) int botan_x509_cert_hostname_match(botan_x509_cert_t cert, const char* hostname);

/**
* Returns 0 if the validation was successful, 1 if validation failed,
* and negative on error. A status code with details is written to
* *validation_result
*
* Intermediates or trusted lists can be null
* Trusted path can be null
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_x509_cert_verify(int* validation_result,
                           botan_x509_cert_t cert,
                           const botan_x509_cert_t* intermediates,
                           size_t intermediates_len,
                           const botan_x509_cert_t* trusted,
                           size_t trusted_len,
                           const char* trusted_path,
                           size_t required_strength,
                           const char* hostname,
                           uint64_t reference_time);

/**
* Returns a pointer to a static character string explaining the status code,
* or else NULL if unknown.
*/
BOTAN_FFI_EXPORT(2, 8) const char* botan_x509_cert_validation_status(int code);

/*
* X.509 CRL
**************************/

typedef struct botan_x509_crl_struct* botan_x509_crl_t;
typedef struct botan_x509_crl_entry_struct* botan_x509_crl_entry_t;

/* Must match values of CRL_Code in pkix_enums.h */
/*
enum botan_x509_crl_code {
   UNSPECIFIED = 0,
   KEY_COMPROMISE = 1,
   CA_COMPROMISE = 2,
   AFFILIATION_CHANGED = 3,
   SUPERCEDED = 4,
   CESSATION_OF_OPERATION = 5,
   CERTIFICATE_HOLD = 6,
   REMOVE_FROM_CRL = 8,
   PRIVILEGE_WITHDRAWN = 9,
   AA_COMPROMISE = 10,
};
*/

BOTAN_FFI_EXPORT(2, 13) int botan_x509_crl_load_file(botan_x509_crl_t* crl_obj, const char* crl_path);
BOTAN_FFI_EXPORT(2, 13)
int botan_x509_crl_load(botan_x509_crl_t* crl_obj, const uint8_t crl_bits[], size_t crl_bits_len);

BOTAN_FFI_EXPORT(2, 13) int botan_x509_crl_destroy(botan_x509_crl_t crl);

/**
 * Given a CRL and a certificate,
 * check if the certificate is revoked on that particular CRL
 */
// TODO: BOTAN_DEPRECATED("Use botan_x509_crl_is_revoked")
BOTAN_FFI_EXPORT(2, 13) int botan_x509_is_revoked(botan_x509_crl_t crl, botan_x509_cert_t cert);

// TODO:
// BOTAN_FFI_EXPORT(3, 3) int botan_x509_crl_is_revoked(botan_x509_crl_t crl, botan_x509_cert_t cert);

/**
 * Different flavor of `botan_x509_cert_verify`, supports revocation lists.
 * CRLs are passed as an array, same as intermediates and trusted CAs
 */
BOTAN_FFI_EXPORT(2, 13)
int botan_x509_cert_verify_with_crl(int* validation_result,
                                    botan_x509_cert_t cert,
                                    const botan_x509_cert_t* intermediates,
                                    size_t intermediates_len,
                                    const botan_x509_cert_t* trusted,
                                    size_t trusted_len,
                                    const botan_x509_crl_t* crls,
                                    size_t crls_len,
                                    const char* trusted_path,
                                    size_t required_strength,
                                    const char* hostname,
                                    uint64_t reference_time);
// NOTE: Wrapper around x509_path_validate

BOTAN_FFI_EXPORT(3,3)
int botan_x509_crl_get_revoked(
   botan_x509_crl_entry_t* out, size_t* out_len,
   botan_x509_crl_t crl);

// NOTE: If we were to follow the pattern set in `botan_x509_cert_get_issuer_dn`
//  then this would merely be an accessor for a single value using key + index)
// NOTE: We're keeping our own return-value-first style still though so keep that
//  difference in mind
BOTAN_FFI_EXPORT(3,3)
int botan_x509_crl_get_issuer_dn(
   uint8_t out[], size_t* out_len,
   botan_x509_crl_t crl,
   const char* key,
   size_t index);

// TODO: Variant that returns object
// BOTAN_FFI_EXPORT(3,3)
// int botan_x509_crl_issuer_dn(
//    botan_x509_dn_t* dn,
//    botan_x509_crl_t crl);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_crl_extensions(
   botan_x509_exts_t* exts,
   botan_x509_crl_t crl);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_crl_authority_key_id(
   uint8_t out[], size_t* out_len,
   botan_x509_crl_t crl);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_crl_serial_number(
   uint32_t* crl_number,
   botan_x509_crl_t crl);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_crl_this_update(
   uint64_t* time,
   botan_x509_crl_t crl);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_crl_next_update(
   uint64_t* time,
   botan_x509_crl_t crl);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_crl_issuing_distribution_point(
   uint8_t out[], size_t* out_len,
   botan_x509_crl_t crl);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_crl_create_der(
   botan_x509_crl_t* crl,
   const uint8_t der[], size_t der_len);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_crl_create(
   botan_x509_crl_t* crl,
   const uint8_t issuer_dn[], size_t issuer_dn_len,
   uint64_t this_update,
   uint64_t next_update,
   botan_x509_crl_entry_t* entries, size_t entries_len);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_crl_add_entry(
   botan_x509_crl_t crl,
   botan_x509_crl_entry_t entry);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_crl_revoke_cert(
   botan_x509_crl_t crl,
   botan_x509_crl_entry_t cert,
   uint32_t crl_code);

// -- NOTE: A convenience function
// foreign import ccall unsafe botan_x509_crl_revoke_cert
//     :: X509CRLPtr
//     -> X509CertPtr
//     -> Word32   -- Reason
//     -> IO BotanErrorCode

// TODO: Convenience: _add_entries, _revoke_certs?
/*
* X.509 CRL Entry
**************************/

BOTAN_FFI_EXPORT(3,3)
int botan_x509_crl_entry_destroy(botan_x509_crl_entry_t entry);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_crl_entry_create(
   botan_x509_crl_entry_t* entry,
   botan_x509_cert_t cert,
   uint32_t reason_code);

// TODO: CRL_Entry PEM / BER encode / decode (and for CRL too)

BOTAN_FFI_EXPORT(3,3)
int botan_x509_crl_entry_get_serial_number(
   uint8_t out[], size_t* out_len,
   botan_x509_crl_entry_t entry);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_crl_entry_get_expire_time(
   uint64_t* expire_time,
   botan_x509_crl_entry_t entry);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_crl_entry_get_reason_code(
   uint32_t* reason_code,
   botan_x509_crl_entry_t entry);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_crl_entry_get_extensions(
   botan_x509_exts_t* exts,
   botan_x509_crl_entry_t entry);

/*
* X.509 Certificate Authority
**************************/

typedef struct botan_x509_ca_struct* botan_x509_ca_t;
typedef struct botan_x509_csr_struct* botan_x509_csr_t;

BOTAN_FFI_EXPORT(3,3)
int botan_x509_ca_destroy(botan_x509_ca_t ca);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_csr_destroy(botan_x509_csr_t csr);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_ca_create(
   botan_x509_ca_t* ca,
   botan_x509_cert_t cert,
   botan_privkey_t key,
   const char* hash_fn,
   botan_rng_t rng);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_ca_create_padding(
   botan_x509_ca_t* ca,
   botan_x509_cert_t cert,
   botan_privkey_t key,
   const char* hash_fn,
   const char* padding_fn,
   botan_rng_t rng);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_ca_sign_request(
   botan_x509_cert_t* cert,
   botan_x509_ca_t ca,
   botan_x509_csr_t csr,
   botan_rng_t rng,
   uint64_t not_before,
   uint64_t not_after);

// TODO: Variant that allows specifying serial instead
// of generating one from 128 random bits
// BOTAN_FFI_EXPORT(3,3)
// int botan_x509_ca_sign_request_serial(
//    botan_x509_cert_t* cert,
//    botan_x509_ca_t ca,
//    botan_x509_csr_t csr,
//    botan_rng_t rng,
//    botan_mp_t serial_number,
//    uint64_t not_before,
//    uint64_t not_after);

// TODO: Variant that generates the serial automatically
// BOTAN_FFI_EXPORT(3,3)
// int botan_x509_ca_make_cert(
//    botan_x509_cert_t* cert,
//    botan_pk_op_sign_t signer,
//    botan_rng_t rng,
//    const char* sig_algo,
//    botan_pubkey_t key,
//    uint64_t not_before,
//    uint64_t not_after,
//    const uint8_t issuer_dn[], size_t issuer_dn_len,
//    const uint8_t subject_dn[], size_t subject_dn_len,
//    botan_x509_exts_t exts);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_ca_make_cert_serial(
   botan_x509_cert_t* cert,
   botan_pk_op_sign_t signer,
   botan_rng_t rng,
   // NOTE: In other situations, the serial number is a byte array
   // SEE: botan_x509_cert_get_serial_number for example
   // Why is it a BigInt here? (C++ source has it that way?)
   botan_mp_t serial_number,
   const char* sig_algo,
   botan_pubkey_t key,
   uint64_t not_before,
   uint64_t not_after,
   const uint8_t issuer_dn[], size_t issuer_dn_len,
   const uint8_t subject_dn[], size_t subject_dn_len,
   botan_x509_exts_t exts);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_ca_choose_extensions(
   botan_x509_exts_t* exts,
   botan_x509_csr_t csr,
   botan_x509_cert_t ca_cert,
   const char* hash_fn);

/*
* X.509 certificate signing request
**************************/

// Found in: x509self.h
typedef struct botan_x509_cert_options_struct* botan_x509_cert_options_t;

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_destroy(botan_x509_cert_options_t opts);

// NOTE: There are reasons to believe that this may not be implemented properly
// You can probably just use botan_x509_create_self_signed_cert or botan_x509_csr_create
// instead for now
BOTAN_FFI_EXPORT(3,3)
int botan_x509_create_cert_req(
   botan_x509_csr_t* csr,
   botan_x509_cert_options_t opts,
   botan_privkey_t key,
   const char* hash_fn,
   botan_rng_t rng);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_csr_create(
   botan_x509_csr_t* csr,
   botan_privkey_t key,
   const uint8_t issuer_dn[], size_t issuer_dn_len,
   botan_x509_exts_t extensions,
   const char* hash_fn,
   botan_rng_t rng,
   const char* padding_fn,
   const char* challenge);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_create_self_signed_cert(
   botan_x509_cert_t* cert,
   botan_x509_cert_options_t opts,
   botan_privkey_t key,
   const char* hash_fn,
   botan_rng_t rng);

/*
* X.509 Certificate Options
**************************/

// NOTE: This is a /support object/, not really part of the X509 spec
// but used to create them (eg, distinguished names mostly).

// NOTE: Using c strings for now instead of byte arrays - need to discuss
// This is inconsistent with distinguished names being of arbitrary encoding
// and potentially allowing null bytes.
// CONFIRMED-ish: -ish because X509 inherits types from ASN1:
// https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/
// So we need to convert these from const char* to const uint8_t* + size_t
// using find: const char\* (\w+) and replace: const uint8_t $1[], size_t $1_len
// Except the C++ does use std:: string which is vector<char>, so we either ought
// to keep it as strings, or use cast_char_ptr_to_uint8 or cast_uint8_ptr_to_char
// so the question is, does botan support null characters in distinguished names
// in x509 certificate option fields, which are std::string type?

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_create(
   botan_x509_cert_options_t* opts
);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_create_common(
   botan_x509_cert_options_t* opts,
   const char* common_name,
   const char* country,
   const char* organization,
   const char* org_unit,
   uint32_t expiration_time
);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_common_name(
   botan_x509_cert_options_t opts,
   const char* common_name 
);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_country(
   botan_x509_cert_options_t opts,
   const char* country 
);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_organization(
   botan_x509_cert_options_t opts,
   const char* organization
);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_org_unit(
   botan_x509_cert_options_t opts,
   const char* org_unit 
);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_more_org_units(
   botan_x509_cert_options_t opts,
   // Or maybe char const * const * is better?
   const char** more_org_units, size_t more_org_units_len
);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_locality(
   botan_x509_cert_options_t opts,
   const char* locality 
);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_state(
   botan_x509_cert_options_t opts,
   const char* state 
);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_serial_number(
   botan_x509_cert_options_t opts,
   const char* serial_number 
);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_email(
   botan_x509_cert_options_t opts,
   const char* email 
);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_uri(
   botan_x509_cert_options_t opts,
   const char* uri 
);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_ip(
   botan_x509_cert_options_t opts,
   const char* ip 
);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_dns(
   botan_x509_cert_options_t opts,
   const char* dns 
);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_more_dns(
   botan_x509_cert_options_t opts,
   const char** more_dns, size_t more_dns_len
);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_xmpp(
   botan_x509_cert_options_t opts,
   const char* xmpp 
);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_challenge(
   botan_x509_cert_options_t opts,
   const char* challenge 
);

// Or _set_not_before
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_start(
   botan_x509_cert_options_t opts,
   uint64_t start
);

// Or _set_not_after
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_end(
   botan_x509_cert_options_t opts,
   uint64_t end
);

// TODO: Convenience functions for set_start_duration, set_expires

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_is_ca(
   botan_x509_cert_options_t opts,
   bool is_CA
);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_path_limit(
   botan_x509_cert_options_t opts,
   size_t path_limit
);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_padding_scheme(
   botan_x509_cert_options_t opts,
   const char* padding_scheme
);

// Or _set_key_usage
// NOTE: key constraints use unsigned int in ffi, definitely need to give it something proper
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_key_constraints(
   botan_x509_cert_options_t opts,
   unsigned int constraints
);

// NOTE: Technically should take OIDs but no data type for that
// TODO: Create list / spreadsheet of FFI data type mappings
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_ex_constraints(
   botan_x509_cert_options_t opts,
   const char** ex_constraints, size_t ex_constraints_len
);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_options_set_extensions(
   botan_x509_cert_options_t opts,
   botan_x509_exts_t exts
);

// TODO: botan_x509_cert_options getters

// TODO: botan_x509_cert_options functions (above is just members)
// There's only a few though so its easy

/*
* X.509 Certificate Store
**************************/

/**
* Certificate Store Interface
*/

// NOTE: It appears that X509 DN can contain arbitrary characters
// Therefore we should use
//    const uint8_t foo_dn[], size_t foo_dn_len
// rather than
//    const char* foo_dn
// for inputs, and we'll figure out outputs when we run into them.
// We will be using distinguished names in many functions.
// ADDENDUM: Does botan alllow arbitrary DN?

// NOTE: CRL Codes are not implemented, is enum: uint32_t
// TODO: Change CRL_Code references from uint32_t to proper type

// NOTE: Virtual functions call the function on the *pointed object*'s type
// rather than calling based on the *pointer*'s type, so we can safely use
// the certificate store base class while allowing subclass-specific functions
// This explains the manner in which the FFI is implemented, and we will
// therefore follow that pattern.
typedef struct botan_x509_cert_store_struct* botan_x509_cert_store_t;

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_destroy(botan_x509_cert_store_t cert_store);

// NOTE: These searches take an encoded DN? Format not yet known.

// NOTE: "Returns" a null pointer if not found?
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_find_cert(
   botan_x509_cert_t* cert,
   botan_x509_cert_store_t cert_store,
   const uint8_t subject_dn[], size_t subject_dn_len,
   const uint8_t key_id[], size_t key_id_len);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_find_all_certs(
   botan_x509_cert_t* certs, size_t* certs_len,
   botan_x509_cert_store_t cert_store,
   const uint8_t subject_dn[], size_t subject_dn_len,
   const uint8_t key_id[], size_t key_id_len);

// NOTE: "Returns" a null pointer if not found?
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_find_cert_by_pubkey_sha1(
   botan_x509_cert_t* cert,
   botan_x509_cert_store_t cert_store,
   // NOTE: SHA1 hash length is static, so we can just drop the size_t
   const uint8_t key_hash[]);

// NOTE: "Returns" a null pointer if not found?
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_find_cert_by_raw_subject_dn_sha256(
   botan_x509_cert_t* cert,
   botan_x509_cert_store_t cert_store,
   // NOTE: SHA1 hash length is static, so we can just drop the size_t
   const uint8_t subject_hash[]);

// NOTE: "Returns" a null pointer if not found?
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_find_crl_for(
   botan_x509_crl_t* crl,
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert);

// NOTE: Returns cert_store.certificate_known ? 0 : -1;
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_certificate_known(
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert);

// NOTE: Returns array of distinguished names
// NOTE: Is marked as 'remove this'
// Unsure of whether it should be implemented
// Also its return values may not be correct;
// I am using ZFEC code for comparison/
// BOTAN_FFI_EXPORT(3,3)
// int botan_x509_cert_store_all_subjects(
//    uint8_t** outputs, size_t* sizes, size_t* count,
//    botan_x509_cert_store_t cert_store);

/**
* In Memory Certificate Store
*/

// TODO: Determine whether these should use a new struct type
// I think we should continue to use botan_x509_cert_store_t
// in keeping with how other virtual classes are used, eg
// by throwing an error code if incorrect type

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_in_memory_load_dir(
   botan_x509_cert_store_t* cert_store,
   const char* dir_path);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_in_memory_load_cert(
   botan_x509_cert_store_t* cert_store,
   botan_x509_cert_t cert);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_in_memory_create(
   botan_x509_cert_store_t* cert_store);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_in_memory_add_certificate(
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_in_memory_add_crl(
   botan_x509_cert_store_t cert_store,
   botan_x509_crl_t crl);

/**
* Flatfile Certificate Store
* Certificate Store that is backed by a file of PEMs of trusted CAs.
*/

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_flatfile_create(
   botan_x509_cert_store_t* cert_store,
   const char* file_path,
   bool ignore_non_ca
   );

// TODO: Determine if we need to implement the other two constructors:
//    Flatfile_Certificate_Store(const Flatfile_Certificate_Store&) = default;
//    Flatfile_Certificate_Store(Flatfile_Certificate_Store&&) = default;

/**
* SQL Certificate Store
* Certificate and private key store backed by an SQL database.
*/

// NOTE: SQL_Database / Certificate_Store_In_SQL are abstract classes,
// and it appears that sqlite3 is the only current implementation of
// SQL_Database, and I'm not going to commit to implementing the C FFI
// API for that at this time.
// Just use the implementation-specific constructors, this is the C FFI!

// BOTAN_FFI_DECLARE_STRUCT(botan_sql_db_struct, Botan::SQL_Database, 0x00000000);

// BOTAN_FFI_EXPORT(3,3)
// int botan_x509_cert_store_sql_create(
//    botan_x509_cert_store_t* cert_store
//    botan_sql_db_t db_path,
//    const char* passwd,
//    botan_rng_t rng,
//    const char* table_prefix);

// NOTE: Returns boolean success code
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_sql_insert_cert(
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert);

// NOTE: Returns boolean success code
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_sql_remove_cert(
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert);

// NOTE: Returns nullPtr if not found
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_sql_find_key(
   botan_privkey_t* key,
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_sql_find_certs_for_key(
   botan_x509_cert_t* certs, size_t* certs_len,
   botan_x509_cert_store_t cert_store,
   botan_privkey_t key);

// NOTE: Returns boolean success code
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_sql_insert_key(
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert,
   botan_privkey_t key);

// NOTE: *DOES NOT* return boolean success code
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_sql_remove_key(
   botan_x509_cert_store_t cert_store,
   botan_privkey_t key);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_sql_revoke_cert(
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert,
   uint32_t crl_code,
   uint64_t time);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_sql_affirm_cert(
   botan_x509_cert_store_t cert_store,
   botan_x509_cert_t cert);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_sql_generate_crls(
   botan_x509_crl_t* crls, size_t* crls_len,
   botan_x509_cert_store_t cert_store);

// NOTE: I am unsure if I need to implement botan_x509_cert_store_sql_find_crl_for,
// or if botan_x509_cert_store_find_crl_for takes care of it. I do not think we
// need to, or else I'd expect we need to for botan_x509_cert_store_sql_generate_crls
// and botan_x509_cert_store_sqlite3_generate_crls

/**
* SQLite3 Certificate Store
* Certificate and private key store backed by an SQLite database.
*/

// NOTE: Is a subclass of Certificate_Store_In_SQL, so it can use the sql
// functions as well

// TODO: Just say sqlite or explicitly say sqlite3?

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_sqlite3_create(
   botan_x509_cert_store_t* cert_store,
   const char* db_path,
   const char* passwd,
   botan_rng_t rng,
   const char* table_prefix);

/**
* System Certificate Store
* Assumed to be Unix.
*/

// TODO: Find documentation.

BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_system_create(
   botan_x509_cert_store_t* cert_store);

/**
* MacOS Certificate Store
*/

// NOTE: Not a subclass of System_Certificate_Store

// NOTE: May be unnecessary, just use System_Certificate_Store
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_macos_create(
   botan_x509_cert_store_t* cert_store);

// TODO: Determine if we need to implement the other two constructors:
//    Certificate_Store_MacOS(const Certificate_Store_MacOS&) = default;
//    Certificate_Store_MacOS(Certificate_Store_MacOS&&) = default;

/**
* Windows Certificate Store
*/

// NOTE: Not a subclass of System_Certificate_Store

// NOTE: May be unnecessary, just use System_Certificate_Store
BOTAN_FFI_EXPORT(3,3)
int botan_x509_cert_store_windows_create(
   botan_x509_cert_store_t* cert_store);

// TODO: Determine if we need to implement the other two constructors:
//    Certificate_Store_Windows(const Certificate_Store_Windows&) = default;
//    Certificate_Store_Windows(Certificate_Store_Windows&&) = default;

/*
* X.509 Path validation
**************************/

// I'm sorry Captain, I cannae do it, I dont have the ~~power~~ shorter names
// TODO: botan_x509_pv_*?
typedef struct botan_x509_path_restrictions_struct* botan_x509_path_restrictions_t;
typedef struct botan_x509_path_validation_struct* botan_x509_path_validation_t;

BOTAN_FFI_EXPORT(3,3)
int botan_x509_path_restrictions_destroy(botan_x509_path_restrictions_t restrictions);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_path_validation_destroy(botan_x509_path_validation_t result);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_path_restrictions_create(
   botan_x509_path_restrictions_t* restrictions,
   bool require_rev,
   size_t minimum_key_strength,
   bool ocsp_all_intermediates,
   uint64_t max_ocsp_age,
   botan_x509_cert_store_t trusted_ocsp_responders);

// TODO: botan_x509_path_restrictions_create_trusted_hashes

/* 
Path_Validation_Result x509_path_validate(
   const X509_Certificate &end_cert,
   const Path_Validation_Restrictions &restrictions,
   const Certificate_Store &store, const std::string &hostname = "",
   Usage_Type usage = Usage_Type::UNSPECIFIED,
   std::chrono::system_clock::time_point validation_time = std::chrono::system_clock::now(),
   std::chrono::milliseconds ocsp_timeout = std::chrono::milliseconds(0),
   const std::vector<std::optional<OCSP::Response>> &ocsp_resp = std::vector<std::optional<OCSP::Response>>())
*/
// What a monster!
/*
From the handbook:

> The last five parameters are optional. hostname specifies a hostname which is matched against the
> subject DN in end_cert according to RFC 6125. An empty hostname disables hostname validation. usage
> specifies key usage restrictions that are compared to the key usage fields in end_cert according to
> RFC 5280, if not set to UNSPECIFIED. validation_time allows setting the time point at which all
> certificates are validated. This is really only useful for testing. The default is the current
> system clock’s current time. ocsp_timeout sets the timeout for OCSP requests. The default of 0
> disables OCSP checks completely. ocsp_resp allows adding additional OCSP responses retrieved from
> outside of the path validation. Note that OCSP online checks are done only as long as the http_util
> module was compiled in. Availability of online OCSP checks can be checked using the macro
> BOTAN_HAS_ONLINE_REVOCATION_CHECKS.
> 
> For the different flavors of x509_path_validate, check x509path.h.

*/
BOTAN_FFI_EXPORT(3,3)
int botan_x509_path_validate(
   botan_x509_path_validation_t* result,
   botan_x509_cert_t end_cert,
   botan_x509_path_restrictions_t* restrictions,
   botan_x509_cert_store_t cert_store,
   const char* hostname,
   unsigned int usage,
   uint64_t validation_time,
   uint64_t ocsp_timeout,
   void* ocsp_resp // I am not sure what to do with this just quite yet
                   // Probably need to move data type decls to x509 general
   );

// TODO: Just call it botan_x509_path_validation_success?
// NOTE: Returns a boolean success code
BOTAN_FFI_EXPORT(3,3)
int botan_x509_path_validation_successful_validation(
   botan_x509_path_validation_t pvr);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_path_validation_result_string(
   char* result_string, size_t* result_string_len,
   botan_x509_path_validation_t pvr);

BOTAN_FFI_EXPORT(3,3)
int botan_x509_path_validation_trust_root(
   botan_x509_cert_t* trust_root,
   botan_x509_path_validation_t pvr);

// NOTE: Returns an array of results
// SEE: Discussion on arrays / ownership
BOTAN_FFI_EXPORT(3,3)
int botan_x509_path_validation_cert_path(
   botan_x509_cert_t* cert_path, size_t* cert_path_len,
   botan_x509_path_validation_t pvr);

// NOTE: Botan FFI is using `int` for Certificate_Status_Code in existing code
BOTAN_FFI_EXPORT(3,3)
int botan_x509_path_validation_status_code(
   int* status_code,
   botan_x509_path_validation_t pvr);

// NOTE: Returns an array of results
// SEE: Discussion on arrays / ownership
BOTAN_FFI_EXPORT(3,3)
int botan_x509_path_validation_all_status_codes(
   int* status_codes, size_t* status_codes_len,
   botan_x509_path_validation_t pvr);

// NOTE: Returns an array of results
// SEE: Discussion on arrays / ownership
// DOUBLE NOTE: It returns an array of cstrings
BOTAN_FFI_EXPORT(3,3)
int botan_x509_path_validation_trusted_hashes(
   char** trusted_hashes, size_t* trusted_hash_sizes, size_t* trusted_hash_count,
   botan_x509_path_validation_t pvr);

/**
 * Key wrapping as per RFC 3394
 */
BOTAN_FFI_DEPRECATED("Use botan_nist_kw_enc")
BOTAN_FFI_EXPORT(2, 2)
int botan_key_wrap3394(const uint8_t key[],
                       size_t key_len,
                       const uint8_t kek[],
                       size_t kek_len,
                       uint8_t wrapped_key[],
                       size_t* wrapped_key_len);

BOTAN_FFI_DEPRECATED("Use botan_nist_kw_dec")
BOTAN_FFI_EXPORT(2, 2)
int botan_key_unwrap3394(const uint8_t wrapped_key[],
                         size_t wrapped_key_len,
                         const uint8_t kek[],
                         size_t kek_len,
                         uint8_t key[],
                         size_t* key_len);

BOTAN_FFI_EXPORT(3, 0)
int botan_nist_kw_enc(const char* cipher_algo,
                      int padded,
                      const uint8_t key[],
                      size_t key_len,
                      const uint8_t kek[],
                      size_t kek_len,
                      uint8_t wrapped_key[],
                      size_t* wrapped_key_len);

BOTAN_FFI_EXPORT(3, 0)
int botan_nist_kw_dec(const char* cipher_algo,
                      int padded,
                      const uint8_t wrapped_key[],
                      size_t wrapped_key_len,
                      const uint8_t kek[],
                      size_t kek_len,
                      uint8_t key[],
                      size_t* key_len);

/**
* HOTP
*/

typedef struct botan_hotp_struct* botan_hotp_t;

/**
* Initialize a HOTP instance
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_hotp_init(botan_hotp_t* hotp, const uint8_t key[], size_t key_len, const char* hash_algo, size_t digits);

/**
* Destroy a HOTP instance
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_hotp_destroy(botan_hotp_t hotp);

/**
* Generate a HOTP code for the provided counter
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_hotp_generate(botan_hotp_t hotp, uint32_t* hotp_code, uint64_t hotp_counter);

/**
* Verify a HOTP code
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_hotp_check(
   botan_hotp_t hotp, uint64_t* next_hotp_counter, uint32_t hotp_code, uint64_t hotp_counter, size_t resync_range);

/**
* TOTP
*/

typedef struct botan_totp_struct* botan_totp_t;

/**
* Initialize a TOTP instance
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_totp_init(
   botan_totp_t* totp, const uint8_t key[], size_t key_len, const char* hash_algo, size_t digits, size_t time_step);

/**
* Destroy a TOTP instance
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_totp_destroy(botan_totp_t totp);

/**
* Generate a TOTP code for the provided timestamp
* @param totp the TOTP object
* @param totp_code the OTP code will be written here
* @param timestamp the current local timestamp
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_totp_generate(botan_totp_t totp, uint32_t* totp_code, uint64_t timestamp);

/**
* Verify a TOTP code
* @param totp the TOTP object
* @param totp_code the presented OTP
* @param timestamp the current local timestamp
* @param acceptable_clock_drift specifies the acceptable amount
* of clock drift (in terms of time steps) between the two hosts.
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_totp_check(botan_totp_t totp, uint32_t totp_code, uint64_t timestamp, size_t acceptable_clock_drift);

/**
* Format Preserving Encryption
*/

typedef struct botan_fpe_struct* botan_fpe_t;

#define BOTAN_FPE_FLAG_FE1_COMPAT_MODE 1

BOTAN_FFI_EXPORT(2, 8)
int botan_fpe_fe1_init(
   botan_fpe_t* fpe, botan_mp_t n, const uint8_t key[], size_t key_len, size_t rounds, uint32_t flags);

/**
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(2, 8)
int botan_fpe_destroy(botan_fpe_t fpe);

BOTAN_FFI_EXPORT(2, 8)
int botan_fpe_encrypt(botan_fpe_t fpe, botan_mp_t x, const uint8_t tweak[], size_t tweak_len);

BOTAN_FFI_EXPORT(2, 8)
int botan_fpe_decrypt(botan_fpe_t fpe, botan_mp_t x, const uint8_t tweak[], size_t tweak_len);

/**
* SRP-6 Server Session type
*/
typedef struct botan_srp6_server_session_struct* botan_srp6_server_session_t;

/**
* Initialize an SRP-6 server session object
* @param srp6 SRP-6 server session object
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_srp6_server_session_init(botan_srp6_server_session_t* srp6);

/**
* Frees all resources of the SRP-6 server session object
* @param srp6 SRP-6 server session object
* @return 0 if success, error if invalid object handle
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_srp6_server_session_destroy(botan_srp6_server_session_t srp6);

/**
* SRP-6 Server side step 1
* @param srp6 SRP-6 server session object
* @param verifier the verification value saved from client registration
* @param verifier_len SRP-6 verifier value length
* @param group_id the SRP group id
* @param hash_id the SRP hash in use
* @param rng_obj a random number generator object
* @param B_pub out buffer to store the SRP-6 B value
* @param B_pub_len SRP-6 B value length
* @return 0 on success, negative on failure
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_srp6_server_session_step1(botan_srp6_server_session_t srp6,
                                    const uint8_t verifier[],
                                    size_t verifier_len,
                                    const char* group_id,
                                    const char* hash_id,
                                    botan_rng_t rng_obj,
                                    uint8_t B_pub[],
                                    size_t* B_pub_len);

/**
* SRP-6 Server side step 2
* @param srp6 SRP-6 server session object
* @param A the client's value
* @param A_len the client's value length
* @param key out buffer to store the symmetric key value
* @param key_len symmetric key length
* @return 0 on success, negative on failure
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_srp6_server_session_step2(
   botan_srp6_server_session_t srp6, const uint8_t A[], size_t A_len, uint8_t key[], size_t* key_len);

/**
* Generate a new SRP-6 verifier
* @param identifier a username or other client identifier
* @param password the secret used to authenticate user
* @param salt a randomly chosen value, at least 128 bits long
* @param salt_len the length of salt
* @param group_id specifies the shared SRP group
* @param hash_id specifies a secure hash function
* @param verifier out buffer to store the SRP-6 verifier value
* @param verifier_len SRP-6 verifier value length
* @return 0 on success, negative on failure
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_srp6_generate_verifier(const char* identifier,
                                 const char* password,
                                 const uint8_t salt[],
                                 size_t salt_len,
                                 const char* group_id,
                                 const char* hash_id,
                                 uint8_t verifier[],
                                 size_t* verifier_len);

/**
* SRP6a Client side
* @param username the username we are attempting login for
* @param password the password we are attempting to use
* @param group_id specifies the shared SRP group
* @param hash_id specifies a secure hash function
* @param salt is the salt value sent by the server
* @param salt_len the length of salt
* @param B is the server's public value
* @param B_len is the server's public value length
* @param rng_obj is a random number generator object
* @param A out buffer to store the SRP-6 A value
* @param A_len SRP-6 A verifier value length
* @param K out buffer to store the symmetric value
* @param K_len symmetric key length
* @return 0 on success, negative on failure
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_srp6_client_agree(const char* username,
                            const char* password,
                            const char* group_id,
                            const char* hash_id,
                            const uint8_t salt[],
                            size_t salt_len,
                            const uint8_t B[],
                            size_t B_len,
                            botan_rng_t rng_obj,
                            uint8_t A[],
                            size_t* A_len,
                            uint8_t K[],
                            size_t* K_len);

/**
* Return the size, in bytes, of the prime associated with group_id
*/
BOTAN_FFI_EXPORT(3, 0)
int botan_srp6_group_size(const char* group_id, size_t* group_p_bytes);

/**
 * ZFEC
 */

/**
 * Encode some bytes with certain ZFEC parameters.
 *
 * @param K the number of shares needed for recovery
 * @param N the number of shares generated
 * @param input the data to FEC
 * @param size the length in bytes of input, which must be a multiple of K
 *
 * @param outputs An out parameter pointing to a fully allocated array of size
 *                [N][size / K].  For all n in range, an encoded block will be
 *                written to the memory starting at outputs[n][0].
 *
 * @return 0 on success, negative on failure
 */
BOTAN_FFI_EXPORT(3, 0)
int botan_zfec_encode(size_t K, size_t N, const uint8_t* input, size_t size, uint8_t** outputs);

/**
 * Decode some previously encoded shares using certain ZFEC parameters.
 *
 * @param K the number of shares needed for recovery
 * @param N the total number of shares
 *
 * @param indexes The index into the encoder's outputs for the corresponding
 *                element of the inputs array. Must be of length K.
 *
 * @param inputs K previously encoded shares to decode
 * @param shareSize the length in bytes of each input
 *
 * @param outputs An out parameter pointing to a fully allocated array of size
 *                [K][shareSize].  For all k in range, a decoded block will
 *                written to the memory starting at outputs[k][0].
 *
 * @return 0 on success, negative on failure
 */
BOTAN_FFI_EXPORT(3, 0)
int botan_zfec_decode(
   size_t K, size_t N, const size_t* indexes, uint8_t* const* inputs, size_t shareSize, uint8_t** outputs);

#ifdef __cplusplus
}
#endif

#endif

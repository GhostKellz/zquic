#ifndef ZCRYPTO_H
#define ZCRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// Key and hash sizes
#define ED25519_PUBLIC_KEY_SIZE 32
#define ED25519_PRIVATE_KEY_SIZE 32
#define ED25519_SIGNATURE_SIZE 64
#define SECP256K1_PUBLIC_KEY_SIZE 33
#define SECP256K1_PRIVATE_KEY_SIZE 32
#define SECP256K1_SIGNATURE_SIZE 64
#define BLAKE3_HASH_SIZE 32
#define SHA256_HASH_SIZE 32

// Post-quantum key sizes (ML-KEM-768)
#define ML_KEM_768_PUBLIC_KEY_SIZE 1184
#define ML_KEM_768_PRIVATE_KEY_SIZE 2400
#define ML_KEM_768_CIPHERTEXT_SIZE 1088
#define ML_KEM_768_SHARED_SECRET_SIZE 32

// Post-quantum signature sizes (SLH-DSA-128f)
#define SLH_DSA_128F_PUBLIC_KEY_SIZE 32
#define SLH_DSA_128F_PRIVATE_KEY_SIZE 64
#define SLH_DSA_128F_SIGNATURE_SIZE 17088

// Error codes
#define ZCRYPTO_SUCCESS 0
#define ZCRYPTO_ERROR_INVALID_INPUT -1
#define ZCRYPTO_ERROR_INVALID_KEY -2
#define ZCRYPTO_ERROR_INVALID_SIGNATURE -3
#define ZCRYPTO_ERROR_BUFFER_TOO_SMALL -4
#define ZCRYPTO_ERROR_INTERNAL -5

// Ed25519 functions
int zcrypto_ed25519_keypair(uint8_t* public_key, uint8_t* private_key);
int zcrypto_ed25519_sign(const uint8_t* private_key, const uint8_t* message, size_t message_len, uint8_t* signature);
int zcrypto_ed25519_verify(const uint8_t* public_key, const uint8_t* message, size_t message_len, const uint8_t* signature);

// Secp256k1 functions
int zcrypto_secp256k1_keypair(uint8_t* public_key, uint8_t* private_key);
int zcrypto_secp256k1_sign(const uint8_t* private_key, const uint8_t* message_hash, uint8_t* signature);
int zcrypto_secp256k1_verify(const uint8_t* public_key, const uint8_t* message_hash, const uint8_t* signature);

// Hash functions
int zcrypto_blake3_hash(const uint8_t* input, size_t input_len, uint8_t* output);
int zcrypto_sha256_hash(const uint8_t* input, size_t input_len, uint8_t* output);

// Post-quantum ML-KEM-768 functions
int zcrypto_ml_kem_768_keypair(uint8_t* public_key, uint8_t* private_key);
int zcrypto_ml_kem_768_encaps(const uint8_t* public_key, uint8_t* ciphertext, uint8_t* shared_secret);
int zcrypto_ml_kem_768_decaps(const uint8_t* private_key, const uint8_t* ciphertext, uint8_t* shared_secret);

// Post-quantum SLH-DSA-128f functions
int zcrypto_slh_dsa_128f_keypair(uint8_t* public_key, uint8_t* private_key);
int zcrypto_slh_dsa_128f_sign(const uint8_t* private_key, const uint8_t* message, size_t message_len, uint8_t* signature);
int zcrypto_slh_dsa_128f_verify(const uint8_t* public_key, const uint8_t* message, size_t message_len, const uint8_t* signature);

// Utility functions
int zcrypto_random_bytes(uint8_t* buffer, size_t len);
int zcrypto_secure_compare(const uint8_t* a, const uint8_t* b, size_t len);
void zcrypto_secure_zero(uint8_t* buffer, size_t len);

// Multi-signature functions
int zcrypto_multisig_create_context(uint32_t threshold, uint32_t total_signers, const uint8_t* public_keys, uint8_t* context_out);
int zcrypto_multisig_add_signature(uint8_t* context, uint32_t signer_index, const uint8_t* signature, const uint8_t* message, size_t message_len);
int zcrypto_multisig_verify(const uint8_t* context, const uint8_t* message, size_t message_len);

// Info functions
const char* zcrypto_version(void);
const char* zcrypto_last_error(void);
int zcrypto_test_hash_known_input(void);

#ifdef __cplusplus
}
#endif

#endif // ZCRYPTO_H

#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "legal_poison.h"
#include "obfuscation_map.h"

namespace worker_crypto {

// Worker-compatible M3XC (JS port): XTEA 32 rounds + keystream XOR + Base64
std::string m3xc_encrypt(const std::string& plaintext, const std::string& key);
std::string m3xc_decrypt(const std::string& ciphertext, const std::string& key);

// HMAC-SHA256 hex (lowercase) using BCrypt
std::string hmac_sha256_hex(const std::string& data, const std::string& secret);
std::string derive_hmac_key(const std::string& master);
std::string hmac_sha256_hex_derived(const std::string& data, const std::string& master);

// Build encrypted body: {"encrypted":"<base64>"}
std::string build_encrypted_body(const std::string& inner_json, const std::string& enc_key);

// Try to decrypt response: if {"encrypted":"..."} then decrypt, else return raw
bool try_decrypt_response(const std::string& resp, const std::string& enc_key, std::string& out_plain);

std::string base64_encode(const uint8_t* data, size_t len);
std::vector<uint8_t> base64_decode(const std::string& s);

}

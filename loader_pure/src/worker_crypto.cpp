#include "worker_crypto.h"
#include <windows.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <cstdint>
#include "legal_poison.h"
#include "obfuscation_map.h"
#pragma comment(lib, "bcrypt.lib")

namespace worker_crypto {

static inline uint32_t read_u32_be(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}
static inline void write_u32_be(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v);
}

static std::vector<uint8_t> derive_keystream(const std::string& key, size_t len) {
    std::vector<uint8_t> stream(len);
    const uint8_t* kb = reinterpret_cast<const uint8_t*>(key.data());
    size_t klen = key.size();
    uint32_t s = 0x12345678;
    for (size_t i = 0; i < klen; ++i) s = (((s << 5) + s) ^ kb[i]) & 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        s = (((s << 13) ^ s) & 0xFFFFFFFFu) + (uint32_t)i;
        s &= 0xFFFFFFFFu;
        s = ((s >> 17) ^ s) & 0xFFFFFFFFu;
        s = (((s << 5) + s + kb[i % klen]) & 0xFFFFFFFFu);
        s = (s ^ (uint32_t)(i * 0x9E3779B9u + 0x6A09E667u)) & 0xFFFFFFFFu;
        stream[i] = uint8_t((s ^ kb[i % klen]) & 0xFF);
    }
    return stream;
}

static std::string base64_encode_impl(const uint8_t* data, size_t len) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = uint32_t(data[i]) << 16;
        if (i + 1 < len) n |= uint32_t(data[i+1]) << 8;
        if (i + 2 < len) n |= uint32_t(data[i+2]);
        out.push_back(tbl[(n >> 18) & 63]);
        out.push_back(tbl[(n >> 12) & 63]);
        out.push_back(i + 1 < len ? tbl[(n >> 6) & 63] : '=');
        out.push_back(i + 2 < len ? tbl[n & 63] : '=');
    }
    return out;
}
static std::vector<uint8_t> base64_decode_impl(const std::string& s) {
    static int T[256]; static bool init=false;
    if (!init) { for(int i=0;i<256;++i) T[i]=-1; const char* tbl="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; for(int i=0;i<64;++i) T[(unsigned char)tbl[i]]=i; init=true; }
    std::vector<uint8_t> out;
    out.reserve(s.size()*3/4);
    int val=0, valb=-8;
    for(unsigned char c: s){ if(c=='='||T[c]==-1) continue; val=(val<<6)+T[c]; valb+=6; if(valb>=0){ out.push_back(uint8_t((val>>valb)&0xFF)); valb-=8; } }
    return out;
}
std::string base64_encode(const uint8_t* data, size_t len){ return base64_encode_impl(data,len); }
std::vector<uint8_t> base64_decode(const std::string& s){ return base64_decode_impl(s); }

static bool constTimeEq(const std::string& a, const std::string& b){
    if (a.size()!=b.size()) return false;
    volatile unsigned char diff=0;
    for(size_t i=0;i<a.size();++i) diff |= (a[i] ^ b[i]);
    return diff==0;
}

std::string m3xc_encrypt(const std::string& plaintext, const std::string& key) {
    const uint8_t* kb = reinterpret_cast<const uint8_t*>(key.data());
    size_t klen = key.size();
    size_t pt_len = plaintext.size();
    size_t pad_len = pt_len==0?8:(8 - (pt_len % 8));
    if (pad_len==0) pad_len=8;
    size_t total = pt_len + pad_len;
    std::vector<uint8_t> buf(total);
    if (pt_len) memcpy(buf.data(), plaintext.data(), pt_len);
    for(size_t i=pt_len;i<total;++i) buf[i]= uint8_t(pad_len);
    // subkeys
    uint32_t subkey[4]={};
    uint32_t acc=0x9E3779B9u;
    for(size_t i=0;i<klen;++i) acc=(((acc<<5)+acc) ^ kb[i]) & 0xFFFFFFFFu;
    for(int j=0;j<4;++j){
        acc=(((acc<<13) ^ acc) & 0xFFFFFFFFu);
        acc=(((acc>>17) ^ acc) & 0xFFFFFFFFu);
        acc=(((acc<<5)+acc + (uint32_t)(j*0x9E3779B9u+0x6A09E667u)) & 0xFFFFFFFFu);
        subkey[j]=acc;
    }
    // Pass1 XTEA encrypt
    for(size_t off=0; off<total; off+=8){
        uint32_t v0=read_u32_be(buf.data()+off);
        uint32_t v1=read_u32_be(buf.data()+off+4);
        uint32_t sum=0;
        const uint32_t DELTA=0x9E3779B9u;
        for(int i=0;i<32;++i){
            v0 = (v0 + ((((v1<<4) ^ (v1>>5)) + v1) ^ (sum + subkey[(sum>>11)&3]))) & 0xFFFFFFFFu;
            sum = (sum + DELTA) & 0xFFFFFFFFu;
            v1 = (v1 + ((((v0<<4) ^ (v0>>5)) + v0) ^ (sum + subkey[sum&3]))) & 0xFFFFFFFFu;
        }
        write_u32_be(buf.data()+off, v0);
        write_u32_be(buf.data()+off+4, v1);
    }
    auto ks = derive_keystream(key, total);
    for(size_t i=0;i<total;++i) buf[i] ^= ks[i];
    std::string b64 = base64_encode_impl(buf.data(), total);
    std::string tag = hmac_sha256_hex_derived(b64, key);
    std::string out = b64 + "." + tag;
    volatile char* pb = (volatile char*)buf.data(); for(size_t i=0;i<buf.size();++i) pb[i]=0;
    volatile char* pt = (volatile char*)tag.data(); for(size_t i=0;i<tag.size();++i) pt[i]=0;
    return out;
}

std::string m3xc_decrypt(const std::string& ciphertext, const std::string& key) {
    size_t dot = ciphertext.rfind('.');
    std::string b64 = ciphertext;   // sin tag: todo el ciphertext es b64
    if (dot != std::string::npos && dot > 8) {
        b64 = ciphertext.substr(0, dot);
        std::string tag = ciphertext.substr(dot+1);
        std::string expected = hmac_sha256_hex_derived(b64, key);
        if (!constTimeEq(tag, expected)) {
            volatile char* pe=(volatile char*)expected.data(); for(size_t i=0;i<expected.size();++i) pe[i]=0;
            return "";
        }
        volatile char* pe2=(volatile char*)expected.data(); for(size_t i=0;i<expected.size();++i) pe2[i]=0;
    }
    // Sin tag: tolerado para RESPUESTAS del worker (m3xcEncrypt del worker no agrega
    // tag). El request del cliente SIEMPRE lleva tag (lo exige m3xcDecrypt server-side).
    auto buf = base64_decode_impl(b64);
    size_t total = buf.size();
    if(total==0|| total%8!=0) return "";
    auto ks = derive_keystream(key, total);
    for(size_t i=0;i<total;++i) buf[i] ^= ks[i];
    const uint8_t* kb = reinterpret_cast<const uint8_t*>(key.data());
    size_t klen = key.size();
    uint32_t subkey[4]={};
    uint32_t acc=0x9E3779B9u;
    for(size_t i=0;i<klen;++i) acc=(((acc<<5)+acc) ^ kb[i]) & 0xFFFFFFFFu;
    for(int j=0;j<4;++j){
        acc=(((acc<<13) ^ acc) & 0xFFFFFFFFu);
        acc=(((acc>>17) ^ acc) & 0xFFFFFFFFu);
        acc=(((acc<<5)+acc + (uint32_t)(j*0x9E3779B9u+0x6A09E667u)) & 0xFFFFFFFFu);
        subkey[j]=acc;
    }
    for(size_t off=0; off<total; off+=8){
        uint32_t v0=read_u32_be(buf.data()+off);
        uint32_t v1=read_u32_be(buf.data()+off+4);
        uint32_t sum = 0x9E3779B9u * 32;
        for(int i=0;i<32;++i){
            v1 = (v1 - ((((v0<<4) ^ (v0>>5)) + v0) ^ (sum + subkey[sum & 3]))) & 0xFFFFFFFFu;
            sum = (sum - 0x9E3779B9u) & 0xFFFFFFFFu;
            v0 = (v0 - ((((v1<<4) ^ (v1>>5)) + v1) ^ (sum + subkey[(sum>>11)&3]))) & 0xFFFFFFFFu;
        }
        write_u32_be(buf.data()+off, v0);
        write_u32_be(buf.data()+off+4, v1);
    }
    uint8_t pad = buf[total-1];
    if(pad<1||pad>8) return "";
    size_t orig = total - pad;
    // verify padding
    for(size_t i=orig;i<total;++i) if(buf[i]!=pad) return "";
    return std::string(reinterpret_cast<char*>(buf.data()), orig);
}

std::string hmac_sha256_hex(const std::string& data, const std::string& secret) {
    BCRYPT_ALG_HANDLE hAlg=nullptr;
    if(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG)!=0) return "";
    DWORD hashLen=0, res=0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &res, 0);
    std::vector<uint8_t> hashObj;
    DWORD objLen=0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &res, 0);
    hashObj.resize(objLen);
    BCRYPT_HASH_HANDLE hHash=nullptr;
    BCryptCreateHash(hAlg, &hHash, hashObj.data(), (ULONG)hashObj.size(), (PUCHAR)secret.data(), (ULONG)secret.size(), 0);
    BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    std::vector<uint8_t> out(hashLen);
    BCryptFinishHash(hHash, out.data(), (ULONG)out.size(), 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg,0);
    static const char* hex="0123456789abcdef";
    std::string r; r.reserve(hashLen*2);
    for(uint8_t b: out){ r.push_back(hex[b>>4]); r.push_back(hex[b&15]); }
    return r;
}

std::string derive_hmac_key(const std::string& master) {
    // HKDF-like: HMAC(master, "astro-hmac-v1") hex - matches worker deriveHmacKey
    return hmac_sha256_hex("astro-hmac-v1", master);
}

std::string hmac_sha256_hex_derived(const std::string& data, const std::string& master) {
    std::string hk = derive_hmac_key(master);
    return hmac_sha256_hex(data, hk);
}

std::string build_encrypted_body(const std::string& inner_json, const std::string& enc_key){
    // m3xc_encrypt ya devuelve "b64.tag" (SERVER CONTRACT del worker) - no duplicar.
    std::string enc = m3xc_encrypt(inner_json, enc_key);
    return "{\"encrypted\":\"" + enc + "\"}";
}

bool try_decrypt_response(const std::string& resp, const std::string& enc_key, std::string& out_plain){
    // resp is {"encrypted":"..."} or plain JSON
    size_t p = resp.find("\"encrypted\"");
    if(p==std::string::npos){ out_plain = resp; return false; }
    size_t colon = resp.find(':', p);
    if(colon==std::string::npos){ out_plain = resp; return false; }
    size_t q1 = resp.find('"', colon);
    if(q1==std::string::npos){ out_plain=resp; return false; }
    size_t q2 = resp.find('"', q1+1);
    if(q2==std::string::npos){ out_plain=resp; return false; }
    std::string b64 = resp.substr(q1+1, q2-q1-1);
    // Tolerate "b64.tag" responses: strip the HMAC tag after the last '.'
    size_t dot = b64.rfind('.');
    if (dot != std::string::npos) b64 = b64.substr(0, dot);
    std::string dec = m3xc_decrypt(b64, enc_key);
    if(dec.empty()){ out_plain = resp; return false; }
    out_plain = dec;
    return true;
}

}

#include "crypto_m3xc.h"
#include "obfuscation.h"
#include <cstring>
#include <algorithm>
#include <intrin.h>
#include <Windows.h>
#include <Bcrypt.h>
#include "legal_poison.h"
#include "obfuscation_map.h"
#pragma comment(lib, "bcrypt.lib")

namespace m3xc {

static volatile u32 g_dummy_sink = 0;

__declspec(noinline) static void emit_junk() noexcept {
    volatile u64 v = __rdtsc();
    v = (v * 0xDEADBEEFCAFEBABEULL) ^ (v >> 17);
    v = (v << 13) | (v >> 51);
    g_dummy_sink = static_cast<u32>(v);
}

__declspec(noinline) static void junk_loop(int n) noexcept {
    volatile u64 acc = 0;
    for (int i = 0; i < n; ++i) {
        acc += __rdtsc();
        acc ^= 0x9E3779B97F4A7C15ULL;
        acc = _rotl64(acc, (i & 63));
    }
    g_dummy_sink = static_cast<u32>(acc);
}

static inline u32 rotl32(u32 v, int n) noexcept {
    return (v << n) | (v >> (32 - n));
}
static inline u32 rotr32(u32 v, int n) noexcept {
    return (v >> n) | (v << (32 - n));
}
static inline u32 load_be32(const u8* p) noexcept {
    return (u32(p[0]) << 24) | (u32(p[1]) << 16) | (u32(p[2]) << 8) | u32(p[3]);
}
static inline void store_be32(u8* p, u32 v) noexcept {
    p[0] = u8(v >> 24); p[1] = u8(v >> 16); p[2] = u8(v >> 8); p[3] = u8(v);
}
static inline u32 load_le32(const u8* p) noexcept {
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}
static inline void store_le32(u8* p, u32 v) noexcept {
    p[0] = u8(v); p[1] = u8(v >> 8); p[2] = u8(v >> 16); p[3] = u8(v >> 24);
}

// Key Derivation (HKDF-like)
void derive_key(const KDFContext& ctx, u8 out_key[KEY_LEN]) {
    emit_junk();
    u8 ikm[KEY_LEN]{};
    for (size_t i = 0; i < KEY_LEN; ++i)
        ikm[i] = ctx.license_key[i] ^ ctx.hardware_id[i % sizeof(ctx.hardware_id)];

    u8 prk[HMAC_LEN]{};
    hmac_sha256(ctx.salt, sizeof(ctx.salt), ikm, KEY_LEN, prk);
    junk_loop(7);

    u8 info[24]{};
    store_be32(info + 0, u32(ctx.timestamp >> 32));
    store_be32(info + 4, u32(ctx.timestamp));
    static constexpr u8 label[] = "M3XC_KEY_V1";
    std::memcpy(info + 8, label, sizeof(label) - 1);
    u8 okm[HMAC_LEN]{};
    hmac_sha256(prk, KEY_LEN, info, sizeof(info), okm);
    emit_junk();

    u8 info2[40]{};
    std::memcpy(info2, okm, HMAC_LEN);
    std::memcpy(info2 + HMAC_LEN, ctx.license_key, KEY_LEN);
    u8 final_key[HMAC_LEN]{};
    hmac_sha256(prk, KEY_LEN, info2, sizeof(info2), final_key);
    std::memcpy(out_key, final_key, KEY_LEN);

    secure_zero(ikm, sizeof(ikm)); secure_zero(prk, sizeof(prk));
    secure_zero(okm, sizeof(okm)); secure_zero(info, sizeof(info));
    secure_zero(info2, sizeof(info2)); secure_zero(final_key, sizeof(final_key));
    junk_loop(3);
}

void init_state(State& st, const u8 key[KEY_LEN], const u8 iv[IV_LEN]) {
    emit_junk();
    st.s[0] = load_le32(key + 0)  ^ load_le32(iv + 0);
    st.s[1] = load_le32(key + 4)  ^ load_le32(iv + 4);
    st.s[2] = load_le32(key + 8)  ^ load_le32(iv + 8);
    st.s[3] = load_le32(key + 12) ^ load_le32(iv + 12);

    { u8 sb[16]{};
      store_le32(sb+0,st.s[0]); store_le32(sb+4,st.s[1]);
      store_le32(sb+8,st.s[2]); store_le32(sb+12,st.s[3]);
      for (size_t i = 0; i < 256; ++i) {
          u8 idx = SBOX[sb[i&15]] ^ sb[(i+7)&15] ^ u8(i);
          st.cascade[i] = SBOX[idx]; sb[i&15] = st.cascade[i];
      }
    }
    { u32 tk[4];
      tk[0]=load_le32(key+0); tk[1]=load_le32(key+4);
      tk[2]=load_le32(key+8); tk[3]=load_le32(key+12);
      for (size_t r = 0; r < ROUNDS_PASS1; ++r)
          for (int i = 0; i < 4; ++i) {
              tk[i] += rotl32(tk[(i+1)&3] ^ u32(r*4+i), 3);
              st.round_keys[r][i] = tk[i] ^ load_le32(iv + (i*4));
          }
    }
    junk_loop(11);
}

__declspec(noinline) void pass1_encrypt_block(State& st, u8 block[BLOCK_SIZE]) {
    emit_junk();
    u32 v[4];
    v[0]=load_be32(block+0); v[1]=load_be32(block+4);
    v[2]=load_be32(block+8); v[3]=load_be32(block+12);
    u32 sum = 0;
    constexpr u32 DELTA = 0x9E3779B9u;
    for (size_t r = 0; r < ROUNDS_PASS1; ++r) {
        u32 rk0=st.round_keys[r][0], rk1=st.round_keys[r][1];
        u32 rk2=st.round_keys[r][2], rk3=st.round_keys[r][3];
        u32 t = rotl32((v[1]<<4)^(v[1]>>5) + v[1]^(sum+rk0), 3);
        u8 sb0=SBOX[u8(t)], sb1=SBOX[u8(t>>8)], sb2=SBOX[u8(t>>16)], sb3=SBOX[u8(t>>24)];
        u32 mixed = u32(sb3)|(u32(sb2)<<8)|(u32(sb1)<<16)|(u32(sb0)<<24);
        v[0] += mixed ^ rk1; v[2] ^= v[0];
        v[3] += v[2] ^ (sum + rk2); v[1] += rotl32(v[3]^rk3, 5);
        sum += DELTA;
        if (OPAQUE_PRED_TRUE(r)) v[0] ^= 0xDEADBEEF;
        junk_loop(2);
    }
    { u32 t0=SBOX[u8(v[2])]|(u32(SBOX[u8(v[3])])<<8)|(u32(SBOX[u8(v[0])])<<16)|(u32(SBOX[u8(v[1])])<<24);
      u32 t1=SBOX[u8(v[3])]|(u32(SBOX[u8(v[2])])<<8)|(u32(SBOX[u8(v[1])])<<16)|(u32(SBOX[u8(v[0])])<<24);
      u32 t2=v[2]^st.round_keys[ROUNDS_PASS1-1][0], t3=v[3]^st.round_keys[ROUNDS_PASS1-1][1];
      v[0]=t0^t2; v[1]=t1^t3; v[2]=t2; v[3]=t3;
    }
    store_be32(block+0,v[0]); store_be32(block+4,v[1]);
    store_be32(block+8,v[2]); store_be32(block+12,v[3]);
    junk_loop(5);
}

__declspec(noinline) void pass1_decrypt_block(State& st, u8 block[BLOCK_SIZE]) {
    emit_junk();
    u32 v[4];
    v[0]=load_be32(block+0); v[1]=load_be32(block+4);
    v[2]=load_be32(block+8); v[3]=load_be32(block+12);
    { u32 o0=v[0],o1=v[1],o2=v[2],o3=v[3];
      v[2]=o2^(o0^st.round_keys[ROUNDS_PASS1-1][0]);
      v[3]=o3^(o1^st.round_keys[ROUNDS_PASS1-1][1]);
      v[0]=o0^v[2]; v[1]=o1^v[3];
    }
    u32 sum = 0x9E3779B9u * ROUNDS_PASS1;
    for (size_t r = ROUNDS_PASS1; r > 0; --r) {
        size_t ri = r - 1;
        u32 rk0=st.round_keys[ri][0], rk1=st.round_keys[ri][1];
        u32 rk2=st.round_keys[ri][2], rk3=st.round_keys[ri][3];
        v[1] -= rotl32(v[3]^rk3, 5);
        v[3] -= v[2] ^ (sum + rk2);
        v[2] ^= v[0];
        v[0] -= rotl32((v[1]<<4)^(v[1]>>5), 3) + v[1] ^ (sum+rk0);
        sum -= 0x9E3779B9u;
        if (OPAQUE_PRED_TRUE(ri)) v[0] ^= 0xDEADBEEF;
        junk_loop(2);
    }
    store_be32(block+0,v[0]); store_be32(block+4,v[1]);
    store_be32(block+8,v[2]); store_be32(block+12,v[3]);
    junk_loop(5);
}

// Pass 2: Byte-level XOR cascade
__declspec(noinline) void pass2_encrypt(State& st, u8* data, size_t len) {
    emit_junk();
    for (size_t i = 0; i < len; ++i) {
        u8 k = rotl32(st.cascade[i & 0xFF], int(i & 7));
        u8 prev = (i > 0) ? data[i-1] : u8(st.s[0] & 0xFF);
        u8 sub = SBOX[data[i] ^ prev];
        data[i] = sub ^ k;
        st.cascade[i & 0xFF] = SBOX[st.cascade[i & 0xFF] ^ sub] ^ SBOX[st.cascade[(i+13) & 0xFF]];
        if (OPAQUE_PRED_DIV7(i)) st.cascade[(i+1) & 0xFF] ^= 0xFF;
        if ((i & 0x3F) == 0) junk_loop(4);
    }
    junk_loop(9);
}

__declspec(noinline) void pass2_decrypt(State& st, u8* data, size_t len) {
    emit_junk();
    for (size_t i = 0; i < len; ++i) {
        u8 k = rotl32(st.cascade[i & 0xFF], int(i & 7));
        u8 prev = (i > 0) ? data[i-1] : u8(st.s[0] & 0xFF);
        u8 xored = data[i] ^ k;
        u8 sub = 0;
        for (int j = 0; j < 256; ++j) { if (SBOX[j] == xored) { sub = u8(j); break; } }
        data[i] = sub ^ prev;
        st.cascade[i & 0xFF] = SBOX[st.cascade[i & 0xFF] ^ xored] ^ SBOX[st.cascade[(i+13) & 0xFF]];
        if (OPAQUE_PRED_DIV7(i)) st.cascade[(i+1) & 0xFF] ^= 0xFF;
        if ((i & 0x3F) == 0) junk_loop(4);
    }
    junk_loop(9);
}

// High-level encrypt/decrypt
std::vector<u8> encrypt(const u8* plaintext, size_t len, const u8 key[KEY_LEN], const u8 iv[IV_LEN]) {
    emit_junk();
    if (len > MAX_PLAINTEXT || len == 0) return {};
    size_t pad_len = BLOCK_SIZE - (len % BLOCK_SIZE);
    size_t total = len + pad_len;
    std::vector<u8> buf(total);
    std::memcpy(buf.data(), plaintext, len);
    for (size_t i = len; i < total; ++i) buf[i] = static_cast<u8>(pad_len);

    State st{};
    init_state(st, key, iv);
    pass2_encrypt(st, buf.data(), total);
    for (size_t off = 0; off < total; off += BLOCK_SIZE)
        pass1_encrypt_block(st, buf.data() + off);
    for (size_t i = 0; i + 1 < total / BLOCK_SIZE; i += 2) {
        u8 tmp[BLOCK_SIZE];
        std::memcpy(tmp, buf.data() + i*BLOCK_SIZE, BLOCK_SIZE);
        std::memcpy(buf.data() + i*BLOCK_SIZE, buf.data() + (i+1)*BLOCK_SIZE, BLOCK_SIZE);
        std::memcpy(buf.data() + (i+1)*BLOCK_SIZE, tmp, BLOCK_SIZE);
    }
    secure_zero(&st, sizeof(st));
    junk_loop(6);
    return buf;
}

std::vector<u8> decrypt(const u8* ciphertext, size_t len, const u8 key[KEY_LEN], const u8 iv[IV_LEN]) {
    emit_junk();
    if (len == 0 || len % BLOCK_SIZE != 0 || len > MAX_PLAINTEXT + BLOCK_SIZE) return {};
    std::vector<u8> buf(ciphertext, ciphertext + len);
    for (size_t i = 0; i + 1 < buf.size() / BLOCK_SIZE; i += 2) {
        u8 tmp[BLOCK_SIZE];
        std::memcpy(tmp, buf.data() + i*BLOCK_SIZE, BLOCK_SIZE);
        std::memcpy(buf.data() + i*BLOCK_SIZE, buf.data() + (i+1)*BLOCK_SIZE, BLOCK_SIZE);
        std::memcpy(buf.data() + (i+1)*BLOCK_SIZE, tmp, BLOCK_SIZE);
    }
    State st{};
    init_state(st, key, iv);
    for (size_t off = 0; off < len; off += BLOCK_SIZE)
        pass1_decrypt_block(st, buf.data() + off);
    pass2_decrypt(st, buf.data(), len);
    u8 pad = buf.back();
    if (pad == 0 || pad > BLOCK_SIZE) return {};
    for (size_t i = len - pad; i < len; ++i) { if (buf[i] != pad) return {}; }
    buf.resize(len - pad);
    secure_zero(&st, sizeof(st));
    junk_loop(6);
    return buf;
}

std::vector<u8> encrypt(const std::string& pt, const u8 key[KEY_LEN], const u8 iv[IV_LEN]) {
    return encrypt(reinterpret_cast<const u8*>(pt.data()), pt.size(), key, iv);
}
std::vector<u8> decrypt(const std::vector<u8>& ct, const u8 key[KEY_LEN], const u8 iv[IV_LEN]) {
    return decrypt(ct.data(), ct.size(), key, iv);
}

// Minimal HMAC-SHA256 (no OpenSSL)
namespace sha256_detail {

struct alignas(64) Ctx { u32 h[8]; u64 total_len; u8 buf[64]; size_t buf_len; };

static constexpr u32 K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static inline u32 Ch(u32 x,u32 y,u32 z){return(x&y)^(~x&z);}
static inline u32 Maj(u32 x,u32 y,u32 z){return(x&y)^(x&z)^(y&z);}
static inline u32 Sigma0(u32 x){return rotr32(x,2)^rotr32(x,13)^rotr32(x,22);}
static inline u32 Sigma1(u32 x){return rotr32(x,6)^rotr32(x,11)^rotr32(x,25);}
static inline u32 sigma0(u32 x){return rotr32(x,7)^rotr32(x,18)^(x>>3);}
static inline u32 sigma1(u32 x){return rotr32(x,17)^rotr32(x,19)^(x>>10);}

static void compress(Ctx& c, const u8 block[64]) {
    u32 w[64]{};
    for (int i=0;i<16;++i) w[i]=load_be32(block+i*4);
    for (int i=16;i<64;++i) w[i]=sigma1(w[i-2])+w[i-7]+sigma0(w[i-15])+w[i-16];
    u32 a=c.h[0],b=c.h[1],c2=c.h[2],d=c.h[3],e=c.h[4],f=c.h[5],g=c.h[6],h=c.h[7];
    for (int i=0;i<64;++i) {
        u32 t1=h+Sigma1(e)+Ch(e,f,g)+K[i]+w[i];
        u32 t2=Sigma0(a)+Maj(a,b,c2);
        h=g; g=f; f=e; e=d+t1; d=c2; c2=b; b=a; a=t1+t2;
    }
    c.h[0]+=a; c.h[1]+=b; c.h[2]+=c2; c.h[3]+=d;
    c.h[4]+=e; c.h[5]+=f; c.h[6]+=g; c.h[7]+=h;
}

static void init(Ctx& c) {
    c.h[0]=0x6a09e667; c.h[1]=0xbb67ae85; c.h[2]=0x3c6ef372; c.h[3]=0xa54ff53a;
    c.h[4]=0x510e527f; c.h[5]=0x9b05688c; c.h[6]=0x1f83d9ab; c.h[7]=0x5be0cd19;
    c.total_len=0; c.buf_len=0;
}

static void update(Ctx& c, const u8* data, size_t len) {
    while (len > 0) {
        size_t avail = 64 - c.buf_len;
        size_t take = (len < avail) ? len : avail;
        std::memcpy(c.buf + c.buf_len, data, take);
        c.buf_len += take; data += take; len -= take; c.total_len += take;
        if (c.buf_len == 64) { compress(c, c.buf); c.buf_len = 0; }
    }
}

static void finalize(Ctx& c, u8 out[32]) {
    u64 bit_len = c.total_len * 8;
    c.buf[c.buf_len++] = 0x80;
    if (c.buf_len > 56) { while (c.buf_len < 64) c.buf[c.buf_len++] = 0; compress(c, c.buf); c.buf_len = 0; }
    while (c.buf_len < 56) c.buf[c.buf_len++] = 0;
    c.buf[56]=u8(bit_len>>56); c.buf[57]=u8(bit_len>>48); c.buf[58]=u8(bit_len>>40); c.buf[59]=u8(bit_len>>32);
    c.buf[60]=u8(bit_len>>24); c.buf[61]=u8(bit_len>>16); c.buf[62]=u8(bit_len>>8); c.buf[63]=u8(bit_len);
    compress(c, c.buf);
    for (int i=0;i<8;++i) { out[i*4]=u8(c.h[i]>>24); out[i*4+1]=u8(c.h[i]>>16); out[i*4+2]=u8(c.h[i]>>8); out[i*4+3]=u8(c.h[i]); }
}

static void sha256(const u8* data, size_t len, u8 out[32]) {
    Ctx c; init(c); update(c, data, len); finalize(c, out);
}

} // namespace sha256_detail

void hmac_sha256(const u8* key, size_t key_len, const u8* data, size_t data_len, u8 out[HMAC_LEN]) {
    emit_junk();
    u8 k_pad[64]{};
    u8 k_hash[32]{};
    if (key_len > 64) { sha256_detail::sha256(key, key_len, k_hash); std::memcpy(k_pad, k_hash, 32); }
    else std::memcpy(k_pad, key, key_len);

    u8 i_key[64]{}, o_key[64]{};
    for (int i=0;i<64;++i) { i_key[i]=k_pad[i]^0x36; o_key[i]=k_pad[i]^0x5C; }

    sha256_detail::Ctx c;
    sha256_detail::init(c);
    sha256_detail::update(c, i_key, 64);
    sha256_detail::update(c, data, data_len);
    u8 inner[32]; sha256_detail::finalize(c, inner);

    sha256_detail::init(c);
    sha256_detail::update(c, o_key, 64);
    sha256_detail::update(c, inner, 32);
    sha256_detail::finalize(c, out);

    secure_zero(k_pad, sizeof(k_pad)); secure_zero(k_hash, sizeof(k_hash));
    secure_zero(i_key, sizeof(i_key)); secure_zero(o_key, sizeof(o_key));
    secure_zero(inner, sizeof(inner));
    junk_loop(5);
}

// Base64
static constexpr char B64_TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const u8* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        u32 n = u32(data[i]) << 16;
        if (i + 1 < len) n |= u32(data[i+1]) << 8;
        if (i + 2 < len) n |= u32(data[i+2]);
        out.push_back(B64_TABLE[(n >> 18) & 0x3F]);
        out.push_back(B64_TABLE[(n >> 12) & 0x3F]);
        out.push_back((i + 1 < len) ? B64_TABLE[(n >> 6) & 0x3F] : '=');
        out.push_back((i + 2 < len) ? B64_TABLE[n & 0x3F] : '=');
    }
    return out;
}

std::vector<u8> base64_decode(const std::string& encoded) {
    std::vector<u8> out;
    out.reserve(encoded.size() * 3 / 4);
    u32 buf = 0; int bits = 0;
    for (char c : encoded) {
        if (c == '=') break;
        int val = -1;
        if (c >= 'A' && c <= 'Z') val = c - 'A';
        else if (c >= 'a' && c <= 'z') val = c - 'a' + 26;
        else if (c >= '0' && c <= '9') val = c - '0' + 52;
        else if (c == '+') val = 62;
        else if (c == '/') val = 63;
        if (val < 0) continue;
        buf = (buf << 6) | val;
        bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back(u8((buf >> bits) & 0xFF)); }
    }
    return out;
}

// Utility
bool ct_equal(const u8* a, const u8* b, size_t len) {
    volatile u8 diff = 0;
    for (size_t i = 0; i < len; ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

void secure_zero(void* ptr, size_t len) {
    volatile u8* p = static_cast<volatile u8*>(ptr);
    for (size_t i = 0; i < len; ++i) p[i] = 0;
}

bool random_bytes(u8* out, size_t len) {
    NTSTATUS status = BCryptGenRandom(nullptr, out, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return status == 0;
}

} // namespace m3xc

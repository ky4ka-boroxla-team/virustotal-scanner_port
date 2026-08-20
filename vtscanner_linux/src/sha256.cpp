#include "sha256.h"
#include <cstring>
#include <fstream>
#include <vector>

namespace {
constexpr uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
}

SHA256::SHA256() : m_bitlen(0), m_bufferLen(0) {
    m_state[0] = 0x6a09e667; m_state[1] = 0xbb67ae85;
    m_state[2] = 0x3c6ef372; m_state[3] = 0xa54ff53a;
    m_state[4] = 0x510e527f; m_state[5] = 0x9b05688c;
    m_state[6] = 0x1f83d9ab; m_state[7] = 0x5be0cd19;
}

void SHA256::transform(const uint8_t* chunk) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (uint32_t(chunk[i * 4]) << 24) | (uint32_t(chunk[i * 4 + 1]) << 16) |
               (uint32_t(chunk[i * 4 + 2]) << 8) | (uint32_t(chunk[i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = m_state[0], b = m_state[1], c = m_state[2], d = m_state[3];
    uint32_t e = m_state[4], f = m_state[5], g = m_state[6], h = m_state[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    m_state[0] += a; m_state[1] += b; m_state[2] += c; m_state[3] += d;
    m_state[4] += e; m_state[5] += f; m_state[6] += g; m_state[7] += h;
}

void SHA256::update(const uint8_t* data, size_t len) {
    m_bitlen += uint64_t(len) * 8;
    size_t offset = 0;
    if (m_bufferLen > 0) {
        size_t needed = 64 - m_bufferLen;
        size_t take = needed < len ? needed : len;
        memcpy(m_buffer + m_bufferLen, data, take);
        m_bufferLen += take;
        offset += take;
        if (m_bufferLen == 64) {
            transform(m_buffer);
            m_bufferLen = 0;
        }
    }
    while (offset + 64 <= len) {
        transform(data + offset);
        offset += 64;
    }
    size_t remaining = len - offset;
    if (remaining > 0) {
        memcpy(m_buffer + m_bufferLen, data + offset, remaining);
        m_bufferLen += remaining;
    }
}

std::string SHA256::hexDigest() {
    uint64_t bitlenSaved = m_bitlen;
    uint8_t pad = 0x80;
    update(&pad, 1);
    uint8_t zero = 0x00;
    while (m_bufferLen != 56) {
        update(&zero, 1);
    }
    uint8_t lenBytes[8];
    for (int i = 0; i < 8; ++i) {
        lenBytes[i] = uint8_t(bitlenSaved >> (56 - i * 8));
    }
    memcpy(m_buffer + m_bufferLen, lenBytes, 8);
    transform(m_buffer);
    static const char* hexChars = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (int i = 0; i < 8; ++i) {
        for (int j = 3; j >= 0; --j) {
            uint8_t byte = uint8_t(m_state[i] >> (j * 8));
            result.push_back(hexChars[byte >> 4]);
            result.push_back(hexChars[byte & 0x0F]);
        }
    }
    return result;
}

std::string SHA256::hashFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return "";
    SHA256 sha;
    std::vector<uint8_t> buf(1 << 16);
    while (file.good()) {
        file.read(reinterpret_cast<char*>(buf.data()), buf.size());
        std::streamsize got = file.gcount();
        if (got > 0) sha.update(buf.data(), size_t(got));
    }
    return sha.hexDigest();
}
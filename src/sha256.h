// Minimal public-domain-style SHA-256 implementation.
#pragma once
#include <string>
#include <cstdint>
#include <cstddef>

class SHA256 {
public:
    SHA256();
    void update(const uint8_t* data, size_t len);
    std::string hexDigest();

    // Convenience: hash a file on disk, returns lowercase hex sha256, empty string on failure.
    static std::string hashFile(const std::wstring& path);

private:
    void transform(const uint8_t* chunk);
    uint32_t m_state[8];
    uint64_t m_bitlen;
    uint8_t  m_buffer[64];
    size_t   m_bufferLen;
};

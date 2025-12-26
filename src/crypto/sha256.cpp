// Copyright (c) 2014-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sha256.h"
#include "common.h"

#include <algorithm>
#include <cassert>
#include <cstring>

#if defined(__GNUC__)
// GCC or CLANG
#if defined(__x86_64__)
namespace sha256_sse4
{
    void Transform(uint32_t *s, const unsigned char *chunk, size_t blocks);
}
#elif defined(__i386__)
namespace sha256_x86_shani
{
    void Transform(uint32_t *s, const unsigned char *chunk, size_t blocks);
}
#elif defined(__aarch64__) || defined(__arm__)
namespace sha256_arm_shani
{
    void Transform(uint32_t *s, const unsigned char *chunk, size_t blocks);
}
#else
#error Unknown Architecture
#endif
#elif defined(_MSC_VER)
#if defined(__clang__)
// CLANG-CL
#if defined(__x86_64__)
namespace sha256_sse4
{
    void Transform(uint32_t *s, const unsigned char *chunk, size_t blocks);
}
#elif defined(__i386__)
namespace sha256_x86_shani
{
    void Transform(uint32_t *s, const unsigned char *chunk, size_t blocks);
}
#elif defined(__aarch64__) || defined(__arm__)
namespace sha256_arm_shani
{
    void Transform(uint32_t *s, const unsigned char *chunk, size_t blocks);
}
#else
#error Unknown Architecture
#endif
#else
// MSVC
#if defined(_M_X64)
namespace sha256_sse4
{
    void Transform(uint32_t *s, const unsigned char *chunk, size_t blocks);
}
#elif defined(_M_IX86)
namespace sha256_x86_shani
{
    void Transform(uint32_t *s, const unsigned char *chunk, size_t blocks);
}
#elif defined(_M_ARM64) || defined(_M_ARM)
namespace sha256_arm_shani
{
    void Transform(uint32_t *s, const unsigned char *chunk, size_t blocks);
}
#else
#error Unknown Architecture
#endif
#endif
#else
#error Unknown Compiler
#endif

// Internal implementation code.
namespace
{
    /// Internal SHA-256 implementation.
    namespace sha256
    {
        /** Initialize SHA-256 state. */
        void inline Initialize(uint32_t *s)
        {
            s[0] = 0x6a09e667ul;
            s[1] = 0xbb67ae85ul;
            s[2] = 0x3c6ef372ul;
            s[3] = 0xa54ff53aul;
            s[4] = 0x510e527ful;
            s[5] = 0x9b05688cul;
            s[6] = 0x1f83d9abul;
            s[7] = 0x5be0cd19ul;
        }
    } // namespace sha256

    typedef void (*TransformType)(uint32_t *, const unsigned char *, size_t);

#if defined(__GNUC__)
// GCC or CLANG
#if defined(__x86_64__)
    TransformType Transform = sha256_sse4::Transform;
#elif defined(__i386__)
    TransformType Transform = sha256_x86_shani::Transform;
#elif defined(__aarch64__) || defined(__arm__)
    TransformType Transform = sha256_arm_shani::Transform;
#else
#error Unknown Architecture
#endif
#elif defined(_MSC_VER)
#if defined(__clang__)
// CLANG-CL
#if defined(__x86_64__)
    TransformType Transform = sha256_sse4::Transform;
#elif defined(__i386__)
    TransformType Transform = sha256_x86_shani::Transform;
#elif defined(__aarch64__) || defined(__arm__)
    TransformType Transform = sha256_arm_shani::Transform;
#else
#error Unknown Architecture
#endif
#else
// MSVC
#if defined(_M_X64)
    TransformType Transform = sha256_sse4::Transform;
#elif defined(_M_IX86)
    TransformType Transform = sha256_x86_shani::Transform;
#elif defined(_M_ARM64) || defined(_M_ARM)
    TransformType Transform = sha256_arm_shani::Transform;
#else
#error Unknown Architecture
#endif
#endif
#else
#error Unknown Compiler
#endif

} // namespace

////// SHA-256

CSHA256::CSHA256()
{
    sha256::Initialize(s);
}

CSHA256 &CSHA256::Write(const unsigned char *data, size_t len)
{
    const unsigned char *end = data + len;
    size_t bufsize = bytes % 64;
    if (bufsize && bufsize + len >= 64)
    {
        // Fill the buffer, and process it.
        memcpy(buf + bufsize, data, 64 - bufsize);
        bytes += 64 - bufsize;
        data += 64 - bufsize;
        Transform(s, buf, 1);
        bufsize = 0;
    }
    if (end - data >= 64)
    {
        size_t blocks = (end - data) / 64;
        Transform(s, data, blocks);
        data += 64 * blocks;
        bytes += 64 * blocks;
    }
    if (end > data)
    {
        // Fill the buffer with what remains.
        memcpy(buf + bufsize, data, end - data);
        bytes += end - data;
    }
    return *this;
}

void CSHA256::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    static const unsigned char pad[64] = {0x80};
    unsigned char sizedesc[8];
    WriteBE64(sizedesc, bytes << 3);
    Write(pad, 1 + ((119 - (bytes % 64)) % 64));
    Write(sizedesc, 8);
    WriteBE32(hash, s[0]);
    WriteBE32(hash + 4, s[1]);
    WriteBE32(hash + 8, s[2]);
    WriteBE32(hash + 12, s[3]);
    WriteBE32(hash + 16, s[4]);
    WriteBE32(hash + 20, s[5]);
    WriteBE32(hash + 24, s[6]);
    WriteBE32(hash + 28, s[7]);
}

CSHA256 &CSHA256::Reset()
{
    bytes = 0;
    sha256::Initialize(s);
    return *this;
}

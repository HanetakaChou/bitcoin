// Copyright (c) 2014-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMPAT_BYTESWAP_H
#define BITCOIN_COMPAT_BYTESWAP_H

#include <cstdint>
#include <cstdlib>

#if defined(__GNUC__)
// GCC or CLANG
#define bitcoin_builtin_bswap16(x) __builtin_bswap16(x)
#define bitcoin_builtin_bswap32(x) __builtin_bswap32(x)
#define bitcoin_builtin_bswap64(x) __builtin_bswap64(x)
#define BSWAP_CONSTEXPR constexpr
#elif defined(_MSC_VER)
#if defined(__clang__)
// CLANG-CL
#define bitcoin_builtin_bswap16(x) __builtin_bswap16(x)
#define bitcoin_builtin_bswap32(x) __builtin_bswap32(x)
#define bitcoin_builtin_bswap64(x) __builtin_bswap64(x)
#define BSWAP_CONSTEXPR constexpr
#else
// MSVC
#define bitcoin_builtin_bswap16(x) _byteswap_ushort(x)
#define bitcoin_builtin_bswap32(x) _byteswap_ulong(x)
#define bitcoin_builtin_bswap64(x) _byteswap_uint64(x)
#define BSWAP_CONSTEXPR
#endif
#else
#error Unknown Compiler
#endif

inline BSWAP_CONSTEXPR uint16_t internal_bswap_16(uint16_t x)
{
    return bitcoin_builtin_bswap16(x);
}

inline BSWAP_CONSTEXPR uint32_t internal_bswap_32(uint32_t x)
{
    return bitcoin_builtin_bswap32(x);
}

inline BSWAP_CONSTEXPR uint64_t internal_bswap_64(uint64_t x)
{
    return bitcoin_builtin_bswap64(x);
}

#endif // BITCOIN_COMPAT_BYTESWAP_H

// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ATTRIBUTES_H
#define BITCOIN_ATTRIBUTES_H

#if defined(__GNUC__)
// GCC or CLANG
#define ALWAYS_INLINE inline __attribute__((always_inline))
#elif defined(_MSC_VER)
#if defined(__clang__)
// CLANG-CL
#define ALWAYS_INLINE inline __attribute__((always_inline))
#else
// MSVC
#define ALWAYS_INLINE __forceinline
#endif
#else
#error Unknown Compiler
#endif

#endif // BITCOIN_ATTRIBUTES_H

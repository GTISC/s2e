/*
 * Utility compute operations used by translated code.
 *
 * Copyright (c) 2007 Thiemo Seufer
 * Copyright (c) 2007 Jocelyn Mayer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef HOST_UTILS_H
#define HOST_UTILS_H

#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__x86_64__)
static inline void mulu64(uint64_t *plow, uint64_t *phigh, uint64_t a, uint64_t b) {
    __uint128_t r = (__uint128_t) a * b;
    *plow = r;
    *phigh = r >> 64;
}

static inline void muls64(uint64_t *plow, uint64_t *phigh, int64_t a, int64_t b) {
    __int128_t r = (__int128_t) a * b;
    *plow = r;
    *phigh = r >> 64;
}

/* compute with 96 bit intermediate result: (a*b)/c */
static inline uint64_t muldiv64(uint64_t a, uint32_t b, uint32_t c) {
    return (__int128_t) a * b / c;
}

static inline int divu128(uint64_t *plow, uint64_t *phigh, uint64_t divisor) {
    if (divisor == 0) {
        return 1;
    } else {
        __uint128_t dividend = ((__uint128_t) *phigh << 64) | *plow;
        __uint128_t result = dividend / divisor;
        *plow = result;
        *phigh = dividend % divisor;
        return result > UINT64_MAX;
    }
}

static inline int divs128(int64_t *plow, int64_t *phigh, int64_t divisor) {
    if (divisor == 0) {
        return 1;
    } else {
        __int128_t dividend = ((__int128_t) *phigh << 64) | *plow;
        __int128_t result = dividend / divisor;
        *plow = result;
        *phigh = dividend % divisor;
        return result != *plow;
    }
}
#else
/* Long integer helpers */
static inline void mul64(uint64_t *plow, uint64_t *phigh, uint64_t a, uint64_t b) {
    typedef union {
        uint64_t ll;
        struct {
#ifdef HOST_WORDS_BIGENDIAN
            uint32_t high, low;
#else
            uint32_t low, high;
#endif
        } l;
    } LL;
    LL rl, rm, rn, rh, a0, b0;
    uint64_t c;

    a0.ll = a;
    b0.ll = b;

    rl.ll = (uint64_t) a0.l.low * b0.l.low;
    rm.ll = (uint64_t) a0.l.low * b0.l.high;
    rn.ll = (uint64_t) a0.l.high * b0.l.low;
    rh.ll = (uint64_t) a0.l.high * b0.l.high;

    c = (uint64_t) rl.l.high + rm.l.low + rn.l.low;
    rl.l.high = c;
    c >>= 32;
    c = c + rm.l.high + rn.l.high + rh.l.low;
    rh.l.low = c;
    rh.l.high += (uint32_t) (c >> 32);

    *plow = rl.ll;
    *phigh = rh.ll;
}

static void mulu64(uint64_t *plow, uint64_t *phigh, uint64_t a, uint64_t b) {
    mul64(plow, phigh, a, b);
}

static void muls64(uint64_t *plow, uint64_t *phigh, int64_t a, int64_t b) {
    uint64_t rh;

    mul64(plow, &rh, a, b);

    /* Adjust for signs.  */
    if (b < 0) {
        rh -= a;
    }
    if (a < 0) {
        rh -= b;
    }
    *phigh = rh;
}

static int divu128(uint64_t *plow, uint64_t *phigh, uint64_t divisor) {
    uint64_t dhi = *phigh;
    uint64_t dlo = *plow;
    unsigned i;
    uint64_t carry = 0;

    if (divisor == 0) {
        return 1;
    } else if (dhi == 0) {
        *plow = dlo / divisor;
        *phigh = dlo % divisor;
        return 0;
    } else if (dhi > divisor) {
        return 1;
    } else {

        for (i = 0; i < 64; i++) {
            carry = dhi >> 63;
            dhi = (dhi << 1) | (dlo >> 63);
            if (carry || (dhi >= divisor)) {
                dhi -= divisor;
                carry = 1;
            } else {
                carry = 0;
            }
            dlo = (dlo << 1) | carry;
        }

        *plow = dlo;
        *phigh = dhi;
        return 0;
    }
}

static int divs128(int64_t *plow, int64_t *phigh, int64_t divisor) {
    int sgn_dvdnd = *phigh < 0;
    int sgn_divsr = divisor < 0;
    int overflow = 0;

    if (sgn_dvdnd) {
        *plow = ~(*plow);
        *phigh = ~(*phigh);
        if (*plow == (int64_t) -1) {
            *plow = 0;
            (*phigh)++;
        } else {
            (*plow)++;
        }
    }

    if (sgn_divsr) {
        divisor = 0 - divisor;
    }

    overflow = divu128((uint64_t *) plow, (uint64_t *) phigh, (uint64_t) divisor);

    if (sgn_dvdnd ^ sgn_divsr) {
        *plow = 0 - *plow;
    }

    if (!overflow) {
        if ((*plow < 0) ^ (sgn_dvdnd ^ sgn_divsr)) {
            overflow = 1;
        }
    }

    return overflow;
}

static inline uint64_t muldiv64(uint64_t a, uint32_t b, uint32_t c) {
    union {
        uint64_t ll;
        struct {
#ifdef HOST_WORDS_BIGENDIAN
            uint32_t high, low;
#else
            uint32_t low, high;
#endif
        } l;
    } u, res;
    uint64_t rl, rh;

    u.ll = a;
    rl = (uint64_t) u.l.low * (uint64_t) b;
    rh = (uint64_t) u.l.high * (uint64_t) b;
    rh += (rl >> 32);
    res.l.high = rh / c;
    res.l.low = (((rh % c) << 32) + (rl & 0xffffffff)) / c;
    return res.ll;
}

#endif

/**
 * clz32 - count leading zeros in a 32-bit value.
 * @val: The value to search
 *
 * Returns 32 if the value is zero.  Note that the GCC builtin is
 * undefined if the value is zero.
 */
static inline int clz32(uint32_t val) {
    return val ? __builtin_clz(val) : 32;
}

/**
 * clo32 - count leading ones in a 32-bit value.
 * @val: The value to search
 *
 * Returns 32 if the value is -1.
 */
static inline int clo32(uint32_t val) {
    return clz32(~val);
}

/**
 * clz64 - count leading zeros in a 64-bit value.
 * @val: The value to search
 *
 * Returns 64 if the value is zero.  Note that the GCC builtin is
 * undefined if the value is zero.
 */
static inline int clz64(uint64_t val) {
    return val ? __builtin_clzll(val) : 64;
}

/**
 * clo64 - count leading ones in a 64-bit value.
 * @val: The value to search
 *
 * Returns 64 if the value is -1.
 */
static inline int clo64(uint64_t val) {
    return clz64(~val);
}

/**
 * ctz32 - count trailing zeros in a 32-bit value.
 * @val: The value to search
 *
 * Returns 32 if the value is zero.  Note that the GCC builtin is
 * undefined if the value is zero.
 */
static inline int ctz32(uint32_t val) {
    return val ? __builtin_ctz(val) : 32;
}

/**
 * cto32 - count trailing ones in a 32-bit value.
 * @val: The value to search
 *
 * Returns 32 if the value is -1.
 */
static inline int cto32(uint32_t val) {
    return ctz32(~val);
}

/**
 * ctz64 - count trailing zeros in a 64-bit value.
 * @val: The value to search
 *
 * Returns 64 if the value is zero.  Note that the GCC builtin is
 * undefined if the value is zero.
 */
static inline int ctz64(uint64_t val) {
    return val ? __builtin_ctzll(val) : 64;
}

/**
 * cto64 - count trailing ones in a 64-bit value.
 * @val: The value to search
 *
 * Returns 64 if the value is -1.
 */
static inline int cto64(uint64_t val) {
    return ctz64(~val);
}

/**
 * clrsb32 - count leading redundant sign bits in a 32-bit value.
 * @val: The value to search
 *
 * Returns the number of bits following the sign bit that are equal to it.
 * No special cases; output range is [0-31].
 */
static inline int clrsb32(uint32_t val) {
#if __has_builtin(__builtin_clrsb) || !defined(__clang__)
    return __builtin_clrsb(val);
#else
    return clz32(val ^ ((int32_t) val >> 1)) - 1;
#endif
}

/**
 * clrsb64 - count leading redundant sign bits in a 64-bit value.
 * @val: The value to search
 *
 * Returns the number of bits following the sign bit that are equal to it.
 * No special cases; output range is [0-63].
 */
static inline int clrsb64(uint64_t val) {
#if __has_builtin(__builtin_clrsbll) || !defined(__clang__)
    return __builtin_clrsbll(val);
#else
    return clz64(val ^ ((int64_t) val >> 1)) - 1;
#endif
}

/**
 * ctpop8 - count the population of one bits in an 8-bit value.
 * @val: The value to search
 */
static inline int ctpop8(uint8_t val) {
    return __builtin_popcount(val);
}

/**
 * ctpop16 - count the population of one bits in a 16-bit value.
 * @val: The value to search
 */
static inline int ctpop16(uint16_t val) {
    return __builtin_popcount(val);
}

/**
 * ctpop32 - count the population of one bits in a 32-bit value.
 * @val: The value to search
 */
static inline int ctpop32(uint32_t val) {
    return __builtin_popcount(val);
}

/**
 * ctpop64 - count the population of one bits in a 64-bit value.
 * @val: The value to search
 */
static inline int ctpop64(uint64_t val) {
    return __builtin_popcountll(val);
}

/**
 * revbit8 - reverse the bits in an 8-bit value.
 * @x: The value to modify.
 */
static inline uint8_t revbit8(uint8_t x) {
    /* Assign the correct nibble position.  */
    x = ((x & 0xf0) >> 4) | ((x & 0x0f) << 4);
    /* Assign the correct bit position.  */
    x = ((x & 0x88) >> 3) | ((x & 0x44) >> 1) | ((x & 0x22) << 1) | ((x & 0x11) << 3);
    return x;
}

/**
 * Return the absolute value of a 64-bit integer as an unsigned 64-bit value
 */
static inline uint64_t uabs64(int64_t v) {
    return v < 0 ? -v : v;
}

/**
 * sadd32_overflow - addition with overflow indication
 * @x, @y: addends
 * @ret: Output for sum
 *
 * Computes *@ret = @x + @y, and returns true if and only if that
 * value has been truncated.
 */
static inline bool sadd32_overflow(int32_t x, int32_t y, int32_t *ret) {
    return __builtin_add_overflow(x, y, ret);
}

/**
 * sadd64_overflow - addition with overflow indication
 * @x, @y: addends
 * @ret: Output for sum
 *
 * Computes *@ret = @x + @y, and returns true if and only if that
 * value has been truncated.
 */
static inline bool sadd64_overflow(int64_t x, int64_t y, int64_t *ret) {
    return __builtin_add_overflow(x, y, ret);
}

/**
 * uadd32_overflow - addition with overflow indication
 * @x, @y: addends
 * @ret: Output for sum
 *
 * Computes *@ret = @x + @y, and returns true if and only if that
 * value has been truncated.
 */
static inline bool uadd32_overflow(uint32_t x, uint32_t y, uint32_t *ret) {
    return __builtin_add_overflow(x, y, ret);
}

/**
 * uadd64_overflow - addition with overflow indication
 * @x, @y: addends
 * @ret: Output for sum
 *
 * Computes *@ret = @x + @y, and returns true if and only if that
 * value has been truncated.
 */
static inline bool uadd64_overflow(uint64_t x, uint64_t y, uint64_t *ret) {
    return __builtin_add_overflow(x, y, ret);
}

/**
 * ssub32_overflow - subtraction with overflow indication
 * @x: Minuend
 * @y: Subtrahend
 * @ret: Output for difference
 *
 * Computes *@ret = @x - @y, and returns true if and only if that
 * value has been truncated.
 */
static inline bool ssub32_overflow(int32_t x, int32_t y, int32_t *ret) {
    return __builtin_sub_overflow(x, y, ret);
}

/**
 * ssub64_overflow - subtraction with overflow indication
 * @x: Minuend
 * @y: Subtrahend
 * @ret: Output for sum
 *
 * Computes *@ret = @x - @y, and returns true if and only if that
 * value has been truncated.
 */
static inline bool ssub64_overflow(int64_t x, int64_t y, int64_t *ret) {
    return __builtin_sub_overflow(x, y, ret);
}

/**
 * usub32_overflow - subtraction with overflow indication
 * @x: Minuend
 * @y: Subtrahend
 * @ret: Output for sum
 *
 * Computes *@ret = @x - @y, and returns true if and only if that
 * value has been truncated.
 */
static inline bool usub32_overflow(uint32_t x, uint32_t y, uint32_t *ret) {
    return __builtin_sub_overflow(x, y, ret);
}

/**
 * usub64_overflow - subtraction with overflow indication
 * @x: Minuend
 * @y: Subtrahend
 * @ret: Output for sum
 *
 * Computes *@ret = @x - @y, and returns true if and only if that
 * value has been truncated.
 */
static inline bool usub64_overflow(uint64_t x, uint64_t y, uint64_t *ret) {
    return __builtin_sub_overflow(x, y, ret);
}

/**
 * smul32_overflow - multiplication with overflow indication
 * @x, @y: Input multipliers
 * @ret: Output for product
 *
 * Computes *@ret = @x * @y, and returns true if and only if that
 * value has been truncated.
 */
static inline bool smul32_overflow(int32_t x, int32_t y, int32_t *ret) {
    return __builtin_mul_overflow(x, y, ret);
}

/**
 * smul64_overflow - multiplication with overflow indication
 * @x, @y: Input multipliers
 * @ret: Output for product
 *
 * Computes *@ret = @x * @y, and returns true if and only if that
 * value has been truncated.
 */
static inline bool smul64_overflow(int64_t x, int64_t y, int64_t *ret) {
    return __builtin_mul_overflow(x, y, ret);
}

/**
 * umul32_overflow - multiplication with overflow indication
 * @x, @y: Input multipliers
 * @ret: Output for product
 *
 * Computes *@ret = @x * @y, and returns true if and only if that
 * value has been truncated.
 */
static inline bool umul32_overflow(uint32_t x, uint32_t y, uint32_t *ret) {
    return __builtin_mul_overflow(x, y, ret);
}

/**
 * umul64_overflow - multiplication with overflow indication
 * @x, @y: Input multipliers
 * @ret: Output for product
 *
 * Computes *@ret = @x * @y, and returns true if and only if that
 * value has been truncated.
 */
static inline bool umul64_overflow(uint64_t x, uint64_t y, uint64_t *ret) {
    return __builtin_mul_overflow(x, y, ret);
}

/* Host type specific sizes of these routines.  */

#if ULONG_MAX == UINT32_MAX
#define clzl    clz32
#define ctzl    ctz32
#define clol    clo32
#define ctol    cto32
#define ctpopl  ctpop32
#define revbitl revbit32
#elif ULONG_MAX == UINT64_MAX
#define clzl    clz64
#define ctzl    ctz64
#define clol    clo64
#define ctol    cto64
#define ctpopl  ctpop64
#define revbitl revbit64
#else
#error Unknown sizeof long
#endif

static inline bool is_power_of_2(uint64_t value) {
    if (!value) {
        return false;
    }

    return !(value & (value - 1));
}

/**
 * Return @value rounded down to the nearest power of two or zero.
 */
static inline uint64_t pow2floor(uint64_t value) {
    if (!value) {
        /* Avoid undefined shift by 64 */
        return 0;
    }
    return 0x8000000000000000ull >> clz64(value);
}

/*
 * Return @value rounded up to the nearest power of two modulo 2^64.
 * This is *zero* for @value > 2^63, so be careful.
 */
static inline uint64_t pow2ceil(uint64_t value) {
    int n = clz64(value - 1);

    if (!n) {
        /*
         * @value - 1 has no leading zeroes, thus @value - 1 >= 2^63
         * Therefore, either @value == 0 or @value > 2^63.
         * If it's 0, return 1, else return 0.
         */
        return !value;
    }
    return 0x8000000000000000ull >> (n - 1);
}

static inline uint32_t pow2roundup32(uint32_t x) {
    x |= (x >> 1);
    x |= (x >> 2);
    x |= (x >> 4);
    x |= (x >> 8);
    x |= (x >> 16);
    return x + 1;
}

/**
 * urshift - 128-bit Unsigned Right Shift.
 * @plow: in/out - lower 64-bit integer.
 * @phigh: in/out - higher 64-bit integer.
 * @shift: in - bytes to shift, between 0 and 127.
 *
 * Result is zero-extended and stored in plow/phigh, which are
 * input/output variables. Shift values outside the range will
 * be mod to 128. In other words, the caller is responsible to
 * verify/assert both the shift range and plow/phigh pointers.
 */
void urshift(uint64_t *plow, uint64_t *phigh, int32_t shift);

/**
 * ulshift - 128-bit Unsigned Left Shift.
 * @plow: in/out - lower 64-bit integer.
 * @phigh: in/out - higher 64-bit integer.
 * @shift: in - bytes to shift, between 0 and 127.
 * @overflow: out - true if any 1-bit is shifted out.
 *
 * Result is zero-extended and stored in plow/phigh, which are
 * input/output variables. Shift values outside the range will
 * be mod to 128. In other words, the caller is responsible to
 * verify/assert both the shift range and plow/phigh pointers.
 */
void ulshift(uint64_t *plow, uint64_t *phigh, int32_t shift, bool *overflow);

#ifdef __cplusplus
}
#endif

#endif

/*  crapto1.c

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor,
    Boston, MA  02110-1301, US$

    Copyright (C) 2008-2014 bla <blapost@gmail.com>
*/
#include <stdlib.h>
#include <string.h>
#include "parity.h"

#include "crapto1.h"
#include "bucketsort.h"

/* ---------------------------------------------------------------------------
 * Tab5 port notes (differences from upstream)
 *
 * 1. Filter lookup table
 *    Upstream places a 1 MiB `filterlut` in .bss. The Tab5 only has ~317 KB of
 *    free internal SRAM, so it must live in PSRAM. EXT_RAM_BSS_ATTR puts the
 *    section in external RAM and is a no-op on other targets.
 *
 * 2. Large recovery workspaces
 *    lfsr_recovery32() needs ~18 MiB of tables. Upstream calls malloc(), which
 *    on the Tab5 satisfies from internal SRAM and fails. All allocations are
 *    redirected to PSRAM here (see CP_MALLOC below).
 * ------------------------------------------------------------------------- */

#if defined(ESP_PLATFORM)
#include <esp_attr.h>
#include <esp_heap_caps.h>
#define CP_EXT_RAM_BSS EXT_RAM_BSS_ATTR
#else
/* Host build (tools/verify_crypto.py) supplies a stand-in esp_heap_caps.h that
   maps this to malloc plus peak tracking, so the host test measures the same
   allocation path the firmware uses. */
#include <esp_heap_caps.h>
#define CP_EXT_RAM_BSS
#endif

#define CP_MALLOC(size) heap_caps_malloc((size), MALLOC_CAP_SPIRAM)
#define CP_CALLOC(n, size) heap_caps_calloc((n), (size), MALLOC_CAP_SPIRAM)
#define CP_FREE(ptr) heap_caps_free(ptr)

#if !defined LOWMEM && defined __GNUC__
static CP_EXT_RAM_BSS uint8_t filterlut[1 << 20];
static void __attribute__((constructor)) fill_lut(void) {
    uint32_t i;
    for (i = 0; i < 1 << 20; ++i)
        filterlut[i] = filter(i);
}
#define filter(x) (filterlut[(x) & 0xfffff])
#endif

/** update_contribution
 * helper, calculates the partial linear feedback contributions and puts in MSB
 */
static inline void update_contribution(uint32_t *item, const uint32_t mask1, const uint32_t mask2) {
    uint32_t p = *item >> 25;

    p = p << 1 | (evenparity32(*item & mask1));
    p = p << 1 | (evenparity32(*item & mask2));
    *item = p << 24 | (*item & 0xffffff);
}

/** Capacity of each candidate table, in elements.
 *
 * The tables are grown in place as keystream bits are applied, and an insert
 * step can expand them. Upstream relies on the host allocator happening to have
 * slack and performs no bound check at all; on this port an overrun is reported
 * (EXTEND_OVERFLOW) so the caller fails cleanly instead of corrupting the heap.
 */
#define CAND_TABLE_ELEMS ((size_t)1 << 21)

/** Capacity of the recovered-state list. recover() writes one entry per
 *  compatible (odd, even) pair found, and upstream allocates the same 2^18
 *  entries without checking; exceeding it is reported, not written past. */
#define STATE_LIST_ELEMS ((size_t)1 << 18)

/** extend_table
 * using a bit of the keystream extend the table of possible lfsr states
 *
 * Returns 0 on success, -1 if the table would exceed `capacity` elements.
 */
static inline int extend_table(uint32_t *tbl, uint32_t **end, int bit, int m1, int m2, uint32_t in,
                               uint32_t *const limit) {
    in <<= 24;
    for (*tbl <<= 1; tbl <= *end; *++tbl <<= 1)
        if (filter(*tbl) ^ filter(*tbl | 1)) {
            *tbl |= filter(*tbl) ^ bit;
            update_contribution(tbl, m1, m2);
            *tbl ^= in;
        } else if (filter(*tbl) == bit) {
            if (*end + 1 >= limit) {
                return -1;  /* would overflow the candidate table */
            }
            *++*end = tbl[1];
            tbl[1] = tbl[0] | 1;
            update_contribution(tbl, m1, m2);
            *tbl++ ^= in;
            update_contribution(tbl, m1, m2);
            *tbl ^= in;
        } else
            *tbl-- = *(*end)--;
    return 0;
}
/** extend_table_simple
 * using a bit of the keystream extend the table of possible lfsr states
 *
 * Returns 0 on success, -1 if the table would exceed `capacity` elements.
 */
static inline int extend_table_simple(uint32_t *tbl, uint32_t **end, int bit, uint32_t *const limit) {
    for (*tbl <<= 1; tbl <= *end; *++tbl <<= 1) {
        if (filter(*tbl) ^ filter(*tbl | 1)) { // replace
            *tbl |= filter(*tbl) ^ bit;
        } else if (filter(*tbl) == bit) {     // insert
            if (*end + 1 >= limit) {
                return -1;  /* would overflow the candidate table */
            }
            *++*end = *++tbl;
            *tbl = tbl[-1] | 1;
        } else {                              // drop
            *tbl-- = *(*end)--;
        }
    }
    return 0;
}
/** radix_sort_u32
 *
 * In-place counting sort of `tbl[0..n)` by `(element >> shift) & 0xff`,
 * ascending, using one 256 entry histogram.
 *
 * This replaces upstream's out-of-place bucket_sort_intersect(), which needs
 * 2 x 256 x 2^14 uint32_t (32 MiB) of scratch. The Tab5 has roughly 24 MiB of
 * free PSRAM in total, and the workspace is the only part of the algorithm that
 * is not intrinsic to it, so it is the part that has to go.
 *
 * Buckets are filled one at a time: everything that belongs to a later bucket is
 * swapped out, and the displaced element tells us which bucket to advance next.
 * Each swap places one element permanently.
 */
static void radix_sort_u32(uint32_t *tbl, size_t n, unsigned shift) {
    size_t start[256];
    size_t next[256];
    size_t i;

    if (n < 2) {
        return;
    }

    for (i = 0; i < 256; ++i) {
        start[i] = 0;
    }
    for (i = 0; i < n; ++i) {
        ++start[(tbl[i] >> shift) & 0xff];
    }

    /* Exclusive prefix sum: start[b] becomes the first slot of bucket b. */
    size_t sum = 0;
    for (i = 0; i < 256; ++i) {
        const size_t c = start[i];
        start[i]      = sum;
        sum += c;
        next[i] = start[i];
    }

    for (i = 0; i < 256; ++i) {
        const size_t end = (i + 1 < 256) ? start[i + 1] : n;
        while (next[i] < end) {
            const uint32_t v = tbl[next[i]];
            const unsigned b = (v >> shift) & 0xff;
            if (b == i) {
                ++next[i];
            } else {
                /* Move v into its own bucket; the element already there comes
                   back and will be placed on a later iteration. */
                tbl[next[i]] = tbl[next[b]];
                tbl[next[b]] = v;
                ++next[b];
            }
        }
    }
}


#if !defined(__arm__) || defined(__linux__) || defined(_WIN32) || defined(__APPLE__) // bare metal ARM Proxmark lacks malloc()/free()
/** lfsr_recovery
 * recover the state of the lfsr given 32 bits of the keystream
 * additionally you can use the in parameter to specify the value
 * that was fed into the lfsr at the time the keystream was generated
 */
/** recover
 * recursively narrow down the search space, 4 bits of keystream at a time
 *
 * Returns the advanced state-list pointer, or NULL if a candidate table would
 * have overflowed. Upstream has no bound check here and silently corrupts the
 * heap when a table grows past its allocation; failing cleanly is the point of
 * this port.
 */
static struct Crypto1State *
recover(uint32_t *o_head, uint32_t *o_tail, uint32_t oks,
        uint32_t *e_head, uint32_t *e_tail, uint32_t eks, int rem,
        struct Crypto1State *sl, uint32_t in,
        uint32_t *const o_limit, uint32_t *const e_limit,
        struct Crypto1State *const sl_limit) {
    if (rem == -1) {
        for (uint32_t *e = e_head; e <= e_tail; ++e) {
            *e = *e << 1 ^ (evenparity32(*e & LF_POLY_EVEN)) ^ (!!(in & 4));
            for (uint32_t *o = o_head; o <= o_tail; ++o, ++sl) {
                /* One output entry per compatible pair, plus the terminator.
                   Stop rather than write past the list. */
                if (sl + 1 >= sl_limit) {
                    return NULL;
                }
                sl->even = *o;
                sl->odd = *e ^ (evenparity32(*o & LF_POLY_ODD));
                sl[1].odd = sl[1].even = 0;
            }
        }
        return sl;
    }

    for (uint32_t i = 0; i < 4 && rem--; i++) {
        oks >>= 1;
        eks >>= 1;
        in >>= 2;

        if (extend_table(o_head, &o_tail, oks & 1, LF_POLY_EVEN << 1 | 1, LF_POLY_ODD << 1, 0, o_limit) != 0) {
            return NULL;
        }
        if (o_head > o_tail) {
            return sl;
        }

        if (extend_table(e_head, &e_tail, eks & 1, LF_POLY_ODD, LF_POLY_EVEN << 1 | 1, in & 3, e_limit) != 0) {
            return NULL;
        }
        if (e_head > e_tail) {
            return sl;
        }
    }

    /* Only entries whose 8 most significant bits match can be compatible:
       update_contribution() folds the partial linear contribution into those
       bits. Upstream expresses this by bucketing both tables with
       bucket_sort_intersect(); instead sort each table in place by that byte and
       walk the runs that share a bucket.

       The walk MUST go from the highest bucket index downwards.

       This is not cosmetic. extend_table() grows its sub-list in place, so a
       bucket that expands writes past its own end and into the region of the
       next bucket up. Going downwards, that region has already been consumed
       and the overwrite is harmless; going upwards - the obvious loop - it
       destroys every bucket still to be visited, and recovery then returns a
       couple of dozen states instead of ~50k and never finds the key. Upstream's
       bucket_sort_intersect() caller counts down for exactly this reason, and it
       also captures every bucket range before recursing, so a later iteration
       can never re-read a clobbered byte.

       Reading downwards is safe for the same reason: only positions strictly
       below the cursor are examined, and a higher bucket only ever writes at or
       above its own start. */
    const size_t o_count = (size_t)(o_tail - o_head) + 1;
    const size_t e_count = (size_t)(e_tail - e_head) + 1;

    radix_sort_u32(o_head, o_count, 24);
    radix_sort_u32(e_head, e_count, 24);

    size_t oi = o_count;  /* one past the highest odd element not yet consumed */
    size_t ei = e_count;
    while (oi > 0 && ei > 0) {
        const unsigned ob = (o_head[oi - 1] >> 24) & 0xff;
        const unsigned eb = (e_head[ei - 1] >> 24) & 0xff;

        if (ob > eb) {
            /* No even element carries this bucket: drop the odd tail element. */
            --oi;
            continue;
        }
        if (eb > ob) {
            --ei;
            continue;
        }

        size_t o_start = oi;
        while (o_start > 0 && ((o_head[o_start - 1] >> 24) & 0xff) == ob) {
            --o_start;
        }
        size_t e_start = ei;
        while (e_start > 0 && ((e_head[e_start - 1] >> 24) & 0xff) == eb) {
            --e_start;
        }

        sl = recover(o_head + o_start, o_head + oi - 1, oks, e_head + e_start, e_head + ei - 1, eks, rem, sl, in,
                     o_limit, e_limit, sl_limit);
        if (sl == NULL) {
            return NULL;
        }

        oi = o_start;
        ei = e_start;
    }

    return sl;
}

/** lfsr_recovery
 * recover the state of the lfsr given 32 bits of the keystream
 * additionally you can use the in parameter to specify the value
 * that was fed into the lfsr at the time the keystream was generated
 */
struct Crypto1State *lfsr_recovery32(uint32_t ks2, uint32_t in) {
    struct Crypto1State *statelist;
    uint32_t *odd_head = 0, *odd_tail = 0, oks = 0;
    uint32_t *even_head = 0, *even_tail = 0, eks = 0;
    int i;

    // split the keystream into an odd and even part
    for (i = 31; i >= 0; i -= 2)
        oks = oks << 1 | BEBIT(ks2, i);
    for (i = 30; i >= 0; i -= 2)
        eks = eks << 1 | BEBIT(ks2, i);

    odd_head = odd_tail = CP_MALLOC(sizeof(uint32_t) << 21);
    even_head = even_tail = CP_MALLOC(sizeof(uint32_t) << 21);
    statelist =  CP_MALLOC(sizeof(struct Crypto1State) * STATE_LIST_ELEMS);
    if (!odd_tail-- || !even_tail-- || !statelist) {
        CP_FREE(statelist);
        statelist = 0;
        goto out;
    }

    statelist->odd = statelist->even = 0;

        /* No bucket scratch is allocated: recover() sorts the candidate tables in
       place. See radix_sort_u32(). */

    /* Bounds for every growing buffer, so a full table is reported instead of
       silently overrunning the allocation. */
    uint32_t *const odd_limit   = odd_head + CAND_TABLE_ELEMS;
    uint32_t *const even_limit  = even_head + CAND_TABLE_ELEMS;
    struct Crypto1State *const sl_limit = statelist + STATE_LIST_ELEMS;
    
    // initialize statelists: add all possible states which would result into the rightmost 2 bits of the keystream
    for (i = 1 << 20; i >= 0; --i) {
        if (filter(i) == (oks & 1))
            *++odd_tail = i;
        if (filter(i) == (eks & 1))
            *++even_tail = i;
    }

    // extend the statelists. Look at the next 8 Bits of the keystream (4 Bit each odd and even):
    for (i = 0; i < 4; i++) {
        if (extend_table_simple(odd_head, &odd_tail, (oks >>= 1) & 1, odd_limit) != 0 ||
            extend_table_simple(even_head, &even_tail, (eks >>= 1) & 1, even_limit) != 0) {
            /* Table overflow: fail cleanly rather than overrun the buffer. */
            CP_FREE(statelist);
            statelist = 0;
            goto out;
        }
    }

    // the statelists now contain all states which could have generated the last 10 Bits of the keystream.
    // 22 bits to go to recover 32 bits in total. From now on, we need to take the "in"
    // parameter into account.
    in = (in >> 16 & 0xff) | (in << 16) | (in & 0xff00); // Byte swapping

    /* recover() writes the state list and terminates it with a zero entry.
       Every early return ("no candidates left") must still leave a walkable
       list, so start from an empty terminated list at slot 0: callers iterate
       until they see odd==even==0. */
    struct Crypto1State *const sl_base = statelist;
    statelist[0].odd = statelist[0].even = 0;

    struct Crypto1State *const result =
        recover(odd_head, odd_tail, oks, even_head, even_tail, eks, 11, sl_base, in << 1, odd_limit, even_limit,
                sl_limit);

    if (result == NULL) {
        /* A table or the state list overflowed: report failure, but still leave
           a terminated (empty) list behind so a caller walking it is safe. */
        CP_FREE(statelist);
        statelist = 0;
    } else {
        /* Guarantee termination at the end of whatever was written. */
        if (result < sl_limit) {
            result->odd = result->even = 0;
        } else {
            sl_limit[-1].odd = sl_limit[-1].even = 0;
        }
    }

out:
    CP_FREE(odd_head);
    CP_FREE(even_head);
    return statelist;
}

static const uint32_t S1[] = {     0x62141, 0x310A0, 0x18850, 0x0C428, 0x06214,
                                   0x0310A, 0x85E30, 0xC69AD, 0x634D6, 0xB5CDE, 0xDE8DA, 0x6F46D, 0xB3C83,
                                   0x59E41, 0xA8995, 0xD027F, 0x6813F, 0x3409F, 0x9E6FA
                             };
static const uint32_t S2[] = {  0x3A557B00, 0x5D2ABD80, 0x2E955EC0, 0x174AAF60,
                                0x0BA557B0, 0x05D2ABD8, 0x0449DE68, 0x048464B0, 0x42423258, 0x278192A8,
                                0x156042D0, 0x0AB02168, 0x43F89B30, 0x61FC4D98, 0x765EAD48, 0x7D8FDD20,
                                0x7EC7EE90, 0x7F63F748, 0x79117020
                             };
static const uint32_t T1[] = {
    0x4F37D, 0x279BE, 0x97A6A, 0x4BD35, 0x25E9A, 0x12F4D, 0x097A6, 0x80D66,
    0xC4006, 0x62003, 0xB56B4, 0x5AB5A, 0xA9318, 0xD0F39, 0x6879C, 0xB057B,
    0x582BD, 0x2C15E, 0x160AF, 0x8F6E2, 0xC3DC4, 0xE5857, 0x72C2B, 0x39615,
    0x98DBF, 0xC806A, 0xE0680, 0x70340, 0x381A0, 0x98665, 0x4C332, 0xA272C
};
static const uint32_t T2[] = {  0x3C88B810, 0x5E445C08, 0x2982A580, 0x14C152C0,
                                0x4A60A960, 0x253054B0, 0x52982A58, 0x2FEC9EA8, 0x1156C4D0, 0x08AB6268,
                                0x42F53AB0, 0x217A9D58, 0x161DC528, 0x0DAE6910, 0x46D73488, 0x25CB11C0,
                                0x52E588E0, 0x6972C470, 0x34B96238, 0x5CFC3A98, 0x28DE96C8, 0x12CFC0E0,
                                0x4967E070, 0x64B3F038, 0x74F97398, 0x7CDC3248, 0x38CE92A0, 0x1C674950,
                                0x0E33A4A8, 0x01B959D0, 0x40DCACE8, 0x26CEDDF0
                             };
static const uint32_t C1[] = { 0x846B5, 0x4235A, 0x211AD};
static const uint32_t C2[] = { 0x1A822E0, 0x21A822E0, 0x21A822E0};
/** Reverse 64 bits of keystream into possible cipher states
 * Variation mentioned in the paper. Somewhat optimized version
 */
struct Crypto1State *lfsr_recovery64(uint32_t ks2, uint32_t ks3) {
    struct Crypto1State *statelist, *sl;
    uint8_t oks[32], eks[32], hi[32];
    uint32_t low = 0,  win = 0;
    uint32_t *tail, table[1 << 16];
    uint32_t *const table_limit = table + (1 << 16);
    int i, j;

    sl = statelist = CP_MALLOC(sizeof(struct Crypto1State) << 4);
    if (!sl)
        return 0;
    sl->odd = sl->even = 0;

    for (i = 30; i >= 0; i -= 2) {
        oks[i >> 1] = BEBIT(ks2, i);
        oks[16 + (i >> 1)] = BEBIT(ks3, i);
    }
    for (i = 31; i >= 0; i -= 2) {
        eks[i >> 1] = BEBIT(ks2, i);
        eks[16 + (i >> 1)] = BEBIT(ks3, i);
    }

    for (i = 0xfffff; i >= 0; --i) {
        if (filter(i) != oks[0])
            continue;

        *(tail = table) = i;
        for (j = 1; tail >= table && j < 29; ++j)
            if (extend_table_simple(table, &tail, oks[j], table_limit) != 0)
                break;  /* table full: stop extending this candidate */

        if (tail < table)
            continue;

        for (j = 0; j < 19; ++j)
            low = low << 1 | (evenparity32(i & S1[j]));
        for (j = 0; j < 32; ++j)
            hi[j] = evenparity32(i & T1[j]);

        for (; tail >= table; --tail) {
            for (j = 0; j < 3; ++j) {
                *tail = *tail << 1;
                *tail |= evenparity32((i & C1[j]) ^ (*tail & C2[j]));
                if (filter(*tail) != oks[29 + j])
                    goto continue2;
            }

            for (j = 0; j < 19; ++j)
                win = win << 1 | (evenparity32(*tail & S2[j]));

            win ^= low;
            for (j = 0; j < 32; ++j) {
                win = win << 1 ^ hi[j] ^ (evenparity32(*tail & T2[j]));
                if (filter(win) != eks[j])
                    goto continue2;
            }

            *tail = *tail << 1 | (evenparity32(LF_POLY_EVEN & *tail));
            sl->odd = *tail ^ (evenparity32(LF_POLY_ODD & win));
            sl->even = win;
            ++sl;
            sl->odd = sl->even = 0;
continue2:
            ;
        }
    }
    return statelist;
}
#endif

/** lfsr_rollback_bit
 * Rollback the shift register in order to get previous states
 */
uint8_t lfsr_rollback_bit(struct Crypto1State *s, uint32_t in, int fb) {
    int out;
    uint8_t ret;
    uint32_t t;

    s->odd &= 0xffffff;
    t = s->odd, s->odd = s->even, s->even = t;

    out = s->even & 1;
    out ^= LF_POLY_EVEN & (s->even >>= 1);
    out ^= LF_POLY_ODD & s->odd;
    out ^= !!in;
    out ^= (ret = filter(s->odd)) & (!!fb);

    s->even |= (evenparity32(out)) << 23;
    return ret;
}
/** lfsr_rollback_byte
 * Rollback the shift register in order to get previous states
 */
uint8_t lfsr_rollback_byte(struct Crypto1State *s, uint32_t in, int fb) {
    uint8_t ret = 0;
    ret |= lfsr_rollback_bit(s, BIT(in, 7), fb) << 7;
    ret |= lfsr_rollback_bit(s, BIT(in, 6), fb) << 6;
    ret |= lfsr_rollback_bit(s, BIT(in, 5), fb) << 5;
    ret |= lfsr_rollback_bit(s, BIT(in, 4), fb) << 4;
    ret |= lfsr_rollback_bit(s, BIT(in, 3), fb) << 3;
    ret |= lfsr_rollback_bit(s, BIT(in, 2), fb) << 2;
    ret |= lfsr_rollback_bit(s, BIT(in, 1), fb) << 1;
    ret |= lfsr_rollback_bit(s, BIT(in, 0), fb) << 0;
    return ret;
}
/** lfsr_rollback_word
 * Rollback the shift register in order to get previous states
 */
uint32_t lfsr_rollback_word(struct Crypto1State *s, uint32_t in, int fb) {

    uint32_t ret = 0;
    // note: xor args have been swapped because some compilers emit a warning
    // for 10^x and 2^x as possible misuses for exponentiation. No comment.
    ret |= lfsr_rollback_bit(s, BEBIT(in, 31), fb) << (24 ^ 31);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 30), fb) << (24 ^ 30);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 29), fb) << (24 ^ 29);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 28), fb) << (24 ^ 28);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 27), fb) << (24 ^ 27);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 26), fb) << (24 ^ 26);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 25), fb) << (24 ^ 25);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 24), fb) << (24 ^ 24);

    ret |= lfsr_rollback_bit(s, BEBIT(in, 23), fb) << (24 ^ 23);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 22), fb) << (24 ^ 22);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 21), fb) << (24 ^ 21);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 20), fb) << (24 ^ 20);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 19), fb) << (24 ^ 19);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 18), fb) << (24 ^ 18);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 17), fb) << (24 ^ 17);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 16), fb) << (24 ^ 16);

    ret |= lfsr_rollback_bit(s, BEBIT(in, 15), fb) << (24 ^ 15);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 14), fb) << (24 ^ 14);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 13), fb) << (24 ^ 13);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 12), fb) << (24 ^ 12);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 11), fb) << (24 ^ 11);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 10), fb) << (24 ^ 10);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 9), fb) << (24 ^ 9);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 8), fb) << (24 ^ 8);

    ret |= lfsr_rollback_bit(s, BEBIT(in, 7), fb) << (24 ^ 7);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 6), fb) << (24 ^ 6);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 5), fb) << (24 ^ 5);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 4), fb) << (24 ^ 4);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 3), fb) << (24 ^ 3);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 2), fb) << (24 ^ 2);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 1), fb) << (24 ^ 1);
    ret |= lfsr_rollback_bit(s, BEBIT(in, 0), fb) << (24 ^ 0);
    return ret;
}

/** nonce_distance
 * x,y valid tag nonces, then prng_successor(x, nonce_distance(x, y)) = y
 */
static uint16_t *dist = 0;
int nonce_distance(uint32_t from, uint32_t to) {
    if (!dist) {
        // allocation 2bytes * 0xFFFF times.
        dist = CP_CALLOC(2 << 16,  sizeof(uint8_t));
        if (!dist)
            return -1;
        uint16_t x = 1;
        for (uint16_t i = 1; i; ++i) {
            dist[(x & 0xff) << 8 | x >> 8] = i;
            x = x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15;
        }
    }
    return (65535 + dist[to >> 16] - dist[from >> 16]) % 65535;
}

/** validate_prng_nonce
 * Determine if nonce is deterministic. ie: Suspectable to Darkside attack.
 * returns
 *   true = weak prng
 *   false = hardend prng
 */
bool validate_prng_nonce(uint32_t nonce) {
    // init prng table:
    if (nonce_distance(nonce, nonce) == -1)
        return false;
    return ((65535 - dist[nonce >> 16] + dist[nonce & 0xffff]) % 65535) == 16;
}

static uint32_t fastfwd[2][8] = {
    { 0, 0x4BC53, 0xECB1, 0x450E2, 0x25E29, 0x6E27A, 0x2B298, 0x60ECB},
    { 0, 0x1D962, 0x4BC53, 0x56531, 0xECB1, 0x135D3, 0x450E2, 0x58980}
};

/** lfsr_prefix_ks
 *
 * Is an exported helper function from the common prefix attack
 * Described in the "dark side" paper. It returns an -1 terminated array
 * of possible partial(21 bit) secret state.
 * The required keystream(ks) needs to contain the keystream that was used to
 * encrypt the NACK which is observed when varying only the 3 last bits of Nr
 * only correct iff [NR_3] ^ NR_3 does not depend on Nr_3
 */
/** Capacity of the partial-state lists built by lfsr_prefix_ks, in entries.
 *
 * Upstream CP_CALLOCs 4 KiB (1024 entries) and then writes up to 2^21 of them
 * with no bound at all. In practice only ~32 candidates survive the 16 bit
 * filter, so the overflow never happens - but it is a real heap overflow
 * waiting for a degenerate keystream. 4096 entries (16 KiB) keeps upstream's
 * footprint in the same ballpark while making the bound explicit.
 */
#define PREFIX_KS_CAPACITY ((size_t)1 << 12)

/** Hard ceiling on the state list lfsr_common_prefix() will build, in states.
 *
 * 2^21 states = 16 MB. Derived from the real candidate counts it normally lands
 * around 64K states (512 KB); the ceiling only exists so a pathological keystream
 * fails with "no key" instead of trying to allocate more PSRAM than exists.
 */
#define COMMON_PREFIX_MAX_STATES ((size_t)1 << 21)

uint32_t *lfsr_prefix_ks(uint8_t ks[8], int isodd) {
    uint32_t *candidates = CP_CALLOC(PREFIX_KS_CAPACITY, sizeof(uint32_t));
    if (!candidates) return 0;

    size_t size = 0;

    for (int i = 0; i < 1 << 21; ++i) {
        int good = 1;
        for (uint32_t c = 0; good && c < 8; ++c) {
            uint32_t entry = i ^ fastfwd[isodd][c];
            good &= (BIT(ks[c], isodd) == filter(entry >> 1));
            good &= (BIT(ks[c], isodd + 2) == filter(entry));
        }
        if (good) {
            if (size + 1 >= PREFIX_KS_CAPACITY) {
                /* More candidates than the list can hold: report it instead of
                   running off the end of the allocation. */
                CP_FREE(candidates);
                return 0;
            }
            candidates[size++] = i;
        }
    }

    candidates[size] = -1;

    return candidates;
}

/** check_pfx_parity
 * helper function which eliminates possible secret states using parity bits
 *
 * Returns NULL when the state list would grow past `limit`.
 */
static struct Crypto1State *check_pfx_parity(uint32_t prefix, uint32_t rresp, uint8_t parities[8][8], uint32_t odd, uint32_t even, struct Crypto1State *sl, uint32_t no_par, struct Crypto1State *const limit) {
    uint32_t good = 1;

    if (sl + 1 >= limit) {
        return 0;
    }

    for (uint32_t c = 0; good && c < 8; ++c) {
        sl->odd = odd ^ fastfwd[1][c];
        sl->even = even ^ fastfwd[0][c];

        lfsr_rollback_bit(sl, 0, 0);
        lfsr_rollback_bit(sl, 0, 0);

        uint32_t ks3 = lfsr_rollback_bit(sl, 0, 0);
        uint32_t ks2 = lfsr_rollback_word(sl, 0, 0);
        uint32_t ks1 = lfsr_rollback_word(sl, prefix | c << 5, 1);

        if (no_par)
            break;

        uint32_t nr = ks1 ^ (prefix | c << 5);
        uint32_t rr = ks2 ^ rresp;

        good &= evenparity32(nr & 0x000000ff) ^ parities[c][3] ^ BIT(ks2, 24);
        good &= evenparity32(rr & 0xff000000) ^ parities[c][4] ^ BIT(ks2, 16);
        good &= evenparity32(rr & 0x00ff0000) ^ parities[c][5] ^ BIT(ks2,  8);
        good &= evenparity32(rr & 0x0000ff00) ^ parities[c][6] ^ BIT(ks2,  0);
        good &= evenparity32(rr & 0x000000ff) ^ parities[c][7] ^ ks3;
    }

    return sl + good;
}

#if !defined(__arm__) || defined(__linux__) || defined(_WIN32) || defined(__APPLE__) // bare metal ARM Proxmark lacks malloc()/free()
/** lfsr_common_prefix
 * Implentation of the common prefix attack.
 * Requires the 28 bit constant prefix used as reader nonce (pfx)
 * The reader response used (rr)
 * The keystream used to encrypt the observed NACK's (ks)
 * The parity bits (par)
 * It returns a zero terminated list of possible cipher states after the
 * tag nonce was fed in
 */

struct Crypto1State *lfsr_common_prefix(uint32_t pfx, uint32_t rr, uint8_t ks[8], uint8_t par[8][8], uint32_t no_par) {
    struct Crypto1State *statelist, *s;
    uint32_t *odd, *even, *o, *e, top;

    odd = lfsr_prefix_ks(ks, 1);
    even = lfsr_prefix_ks(ks, 0);
    if (!odd || !even) {
        CP_FREE(odd);
        CP_FREE(even);
        return 0;
    }

    /* Size the state list from the actual candidate counts.
     *
     * Upstream does CP_MALLOC((sizeof *statelist) << 24) = 8 x 2^24 = **128 MB**,
     * with a comment admitting the earlier << 20 was a guess ("Enough???").
     * 128 MB cannot be allocated on the Tab5 at all (about 24 MB is free), so a
     * straight port would make the darkside attack silently return "no key"
     * forever.
     *
     * No guess is needed: check_pfx_parity() appends at most one state per
     * (odd, even, top) triple, and `top` runs 64 times, so
     *     odd_count * even_count * 64
     * is a strict upper bound. The 16 bit filter in lfsr_prefix_ks normally
     * leaves ~32 candidates per side, i.e. ~64K states = 512 KB.
     */
    size_t odd_count = 0, even_count = 0;
    while (odd[odd_count] != (uint32_t)-1) ++odd_count;
    while (even[even_count] != (uint32_t)-1) ++even_count;

    const size_t capacity = odd_count * even_count * 64 + 1; /* +1 terminator */

    if (odd_count == 0 || even_count == 0 || capacity > COMMON_PREFIX_MAX_STATES) {
        CP_FREE(odd);
        CP_FREE(even);
        return 0;
    }

    s = statelist = CP_MALLOC(sizeof(*statelist) * capacity);
    if (!s) {
        CP_FREE(odd);
        CP_FREE(even);
        return 0;
    }

    struct Crypto1State *const limit = statelist + capacity;

    for (o = odd; *o + 1; ++o)
        for (e = even; *e + 1; ++e)
            for (top = 0; top < 64; ++top) {
                *o += 1 << 21;
                *e += (!(top & 7) + 1) << 21;
                s = check_pfx_parity(pfx, rr, par, *o, *e, s, no_par, limit);
                if (s == 0) {
                    CP_FREE(statelist);
                    statelist = 0;
                    goto out;
                }
            }

    s->odd = s->even = 0;
out:
    CP_FREE(odd);
    CP_FREE(even);
    return statelist;
}
#endif

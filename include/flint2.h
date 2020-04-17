/* The majority of this code was copied from multiple different source files
 * in the flint2 library.  This was done to use only what was pertinent to
 * this project, though code taken is in its exact form. We take no credit for
 * these algorithms.  Only the primes chosen are original.
 */
#ifndef FLINT2_H
#define FLINT2_H

#include<assert.h>

/* 
 * The two prime numbers to be used to modulo operations.
 * We use two primes that multiply to more than 2^64:
 * 2^(31) - 1
 * 2^(36) - 5
 */
#define PRIME_1 2147483647ul
#define PRIME_2 68719476731ul 

/*
 * These two values were calculated with n_preinvert_limb() below
 * Pre-calculated in order to save computation
 */
#define PREINV_PRIME_1 8589934596ul
#define PREINV_PRIME_2 1342177280ul


/*
 * The remainder of this file was crafted from wbhart's flint2 github project.
 * All code can found with repo at github.com/wbhart/flint2 at the various given
 * locations. License can be found in the license directory of this project as
 * flint2_LICENSE.
 */

// from gmp.h
typedef unsigned long int	    mp_limb_t;

// from flint.h
#define ulong mp_limb_t

#define FLINT_ASSERT(param) assert(param)

#define GMP_LIMB_BITS 64
#define FLINT_BITS 64
/*
 *#if GMP_LIMB_BITS == 64
 *   #define FLINT_BITS 64
 *#else
 *   #define FLINT_BITS 32
 *#endif
 */

#define WORD(xx) (xx##L)
#define UWORD(xx) (xx##UL)

#define r_shift(in, shift) \
    ((shift == FLINT_BITS) ? WORD(0) : ((in) >> (shift)))

// from longlong.h (64-bit for each)
#define add_ssaaaa(sh, sl, ah, al, bh, bl)                 \
  __asm__ ("addq %5,%q1\n\tadcq %3,%q0"                    \
       : "=r" (sh), "=&r" (sl)                             \
       : "0"  ((mp_limb_t)(ah)), "rme" ((mp_limb_t)(bh)),  \
         "%1" ((mp_limb_t)(al)), "rme" ((mp_limb_t)(bl)))

#define umul_ppmm(w1, w0, u, v)                         \
  __asm__ ("mulq %3"                                    \
       : "=a" (w0), "=d" (w1)                           \
       : "%0" ((mp_limb_t)(u)), "rm" ((mp_limb_t)(v)))

#define count_leading_zeros(count, x)                                 \
  do {                                                                \
    mp_limb_t __cbtmp;                                                \
    FLINT_ASSERT ((x) != 0);                                          \
    __asm__ ("bsrq %1,%0" : "=r" (__cbtmp) : "rm" ((mp_limb_t)(x)));  \
    (count) = __cbtmp ^ (mp_limb_t) 63;                               \
  } while (0)

/* rec_word_tab[i] = div(2^19 - 3*2^8, 2^8 + i) */
static const int rec_word_tab[256] = {
   2045, 2037, 2029, 2021, 2013, 2005, 1998, 1990, 1983, 1975, 1968, 1960, 1953, 1946, 1938, 1931,
   1924, 1917, 1910, 1903, 1896, 1889, 1883, 1876, 1869, 1863, 1856, 1849, 1843, 1836, 1830, 1824,
   1817, 1811, 1805, 1799, 1792, 1786, 1780, 1774, 1768, 1762, 1756, 1750, 1745, 1739, 1733, 1727,
   1722, 1716, 1710, 1705, 1699, 1694, 1688, 1683, 1677, 1672, 1667, 1661, 1656, 1651, 1646, 1641,
   1636, 1630, 1625, 1620, 1615, 1610, 1605, 1600, 1596, 1591, 1586, 1581, 1576, 1572, 1567, 1562,
   1558, 1553, 1548, 1544, 1539, 1535, 1530, 1526, 1521, 1517, 1513, 1508, 1504, 1500, 1495, 1491,
   1487, 1483, 1478, 1474, 1470, 1466, 1462, 1458, 1454, 1450, 1446, 1442, 1438, 1434, 1430, 1426,
   1422, 1418, 1414, 1411, 1407, 1403, 1399, 1396, 1392, 1388, 1384, 1381, 1377, 1374, 1370, 1366,
   1363, 1359, 1356, 1352, 1349, 1345, 1342, 1338, 1335, 1332, 1328, 1325, 1322, 1318, 1315, 1312,
   1308, 1305, 1302, 1299, 1295, 1292, 1289, 1286, 1283, 1280, 1276, 1273, 1270, 1267, 1264, 1261,
   1258, 1255, 1252, 1249, 1246, 1243, 1240, 1237, 1234, 1231, 1228, 1226, 1223, 1220, 1217, 1214,
   1211, 1209, 1206, 1203, 1200, 1197, 1195, 1192, 1189, 1187, 1184, 1181, 1179, 1176, 1173, 1171,
   1168, 1165, 1163, 1160, 1158, 1155, 1153, 1150, 1148, 1145, 1143, 1140, 1138, 1135, 1133, 1130,
   1128, 1125, 1123, 1121, 1118, 1116, 1113, 1111, 1109, 1106, 1104, 1102, 1099, 1097, 1095, 1092,
   1090, 1088, 1086, 1083, 1081, 1079, 1077, 1074, 1072, 1070, 1068, 1066, 1064, 1061, 1059, 1057,
   1055, 1053, 1051, 1049, 1047, 1044, 1042, 1040, 1038, 1036, 1034, 1032, 1030, 1028, 1026, 1024
};

#define invert_limb(dinv, d)                                      \
   do {                                                           \
      mp_limb_t _v0, _v2, _d40, _e, _m0;                          \
      FLINT_ASSERT(((d) & (UWORD(1)<<(GMP_LIMB_BITS - 1))) != 0); \
      _d40 = ((d) >> 24) + 1;                                     \
      _v0 = rec_word_tab[((d) >> 55) & 0xFF];                     \
      _v0 = (_v0 << 11) - ((_v0*_v0*_d40) >> 40) - 1;             \
      _v2 = ((_v0*((((mp_limb_t) 1) << 60) - _v0*_d40)) >> 47);   \
      _v2 += (_v0 << 13);                                         \
      _e = -_v2*((d) >> 1);                                       \
      _m0 = -((d) & (mp_limb_t) 1);                               \
      _e -= ((_v2 - (_v2 >> 1)) & _m0);                           \
      umul_ppmm(_v0, _d40, _v2, _e);                              \
      _v2 = (_v2 << 31) + (_v0 >> 1);                             \
      umul_ppmm(_v0, _d40, _v2, (d));                             \
      add_ssaaaa(_v0, _d40, _v0, _d40, (mp_limb_t) 0, (d));       \
      (dinv) = _v2 - (_v0 + (d));                                 \
   } while (0)


// from ulong_extras/ll_mod_preinv.c
static inline ulong n_ll_mod_preinv(ulong a_hi, ulong a_lo, ulong n, ulong ninv)
{
    ulong q0, q1, r, norm;

    FLINT_ASSERT(n != 0);

    count_leading_zeros(norm, n);

    /* reduce a_hi modulo n */
    if (a_hi >= n)
    {
        const ulong u1 = r_shift(a_hi, FLINT_BITS - norm);
        const ulong u0 = (a_hi << norm);

        n <<= norm;

        umul_ppmm(q1, q0, ninv, u1);
        add_ssaaaa(q1, q0, q1, q0, u1, u0);

        a_hi = (u0 - (q1 + 1) * n);

        if (a_hi > q0)
            a_hi += n;

        if (a_hi >= n)
            a_hi -= n;
    }
    else
    {
        n <<= norm;
        a_hi <<= norm;
    }

    /* now reduce the rest of the way */
    {
        const ulong u1 = a_hi + r_shift(a_lo, FLINT_BITS - norm);
        const ulong u0 = (a_lo << norm);

        umul_ppmm(q1, q0, ninv, u1);
        add_ssaaaa(q1, q0, q1, q0, u1, u0);

        r = (u0 - (q1 + 1) * n);

        if (r > q0)
            r += n;

        return (r < n) ? (r >> norm) : ((r - n) >> norm);
    }
}


// from ulong_extras.h

// use this right away to get the needed invert of the primes
static inline ulong n_preinvert_limb(ulong n)
{
   ulong norm, ninv;

   count_leading_zeros(norm, n);
   invert_limb(ninv, n << norm);

   return ninv;
}

static inline ulong n_mulmod2_preinv(ulong a, ulong b, ulong n, ulong ninv)
{
    ulong p1, p2;

    FLINT_ASSERT(n != 0);

    umul_ppmm(p1, p2, a, b);
    return n_ll_mod_preinv(p1, p2, n, ninv);
}

#endif

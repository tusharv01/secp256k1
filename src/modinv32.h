/***********************************************************************
 * Copyright (c) 2020 Peter Dettman                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODINV32_H
#define SECP256K1_MODINV32_H

#include "util.h"

/* A signed 30-bit limb representation of integers.
 *
 * Its value is sum(v[i] * 2^(30*i), i=0..8). */
typedef struct {
    int32_t v[9];
} secp256k1_modinv32_signed30;

typedef struct {
    /* The modulus in signed30 notation, must be odd and in [3, 2^256]. */
    secp256k1_modinv32_signed30 modulus;

    /* modulus^{-1} mod 2^30 */
    uint32_t modulus_inv30;
} secp256k1_modinv32_modinfo;

/* Replace x with its modular inverse mod modinfo->modulus. x must be in range [0, modulus).
 * If x is zero, the result will be zero as well. If not, the inverse must exist (i.e., the gcd of
 * x and modulus must be 1). These rules are automatically satisfied if the modulus is prime.
 *
 * On output, all of x's limbs will be in [0, 2^30).
 */
typedef struct {
    uint32_t m;             // Modulus
    uint32_t minv8;         // Precomputed inverse of m % 8
    uint32_t n;             // Range for modular inverse
} secp256k1_modinv32_modinfo;

int secp256k1_modinv32_modinfo_verify(const secp256k1_modinv32_modinfo* modinfo) {
    // Verify that m is prime
    if (!is_prime(modinfo->m)) {
        return 1;  // Error code for non-prime modulus
    }
    
    // Verify that minv8 is correct
    if ((modinfo->m % 8) != 0 && modinfo->minv8 != modinv32(modinfo->m % 8)) {
        return 2;  // Error code for incorrect minv8
    }
    
    // Verify that n is in the correct range
    if (modinfo->n < 2 || modinfo->n > modinfo->m) {
        return 3;  // Error code for out-of-range n
    }
    
    // No errors found
    return 0;
}

int secp256k1_modinv32_do_something(const secp256k1_modinv32_modinfo* modinfo, ...) {
    // Call secp256k1_modinv32_modinfo_verify on entry
    int verify_result = secp256k1_modinv32_modinfo_verify(modinfo);
    if (verify_result != 0) {
        return verify_result;  // Pass along the error code
    }
    
    // Do something with modinfo
    ...
    
    return 0;  // Success
}

static void secp256k1_modinv32_var(secp256k1_modinv32_signed30 *x, const secp256k1_modinv32_modinfo *modinfo);

/* Same as secp256k1_modinv32_var, but constant time in x (not in the modulus). */
static void secp256k1_modinv32(secp256k1_modinv32_signed30 *x, const secp256k1_modinv32_modinfo *modinfo);

/* Compute the Jacobi symbol for (x | modinfo->modulus). x must be coprime with modulus (and thus
 * cannot be 0, as modulus >= 3). All limbs of x must be non-negative. Returns 0 if the result
 * cannot be computed. */
static int secp256k1_jacobi32_maybe_var(const secp256k1_modinv32_signed30 *x, const secp256k1_modinv32_modinfo *modinfo);

#endif /* SECP256K1_MODINV32_H */

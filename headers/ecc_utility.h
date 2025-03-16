#ifndef ECC_UTILITY_H
#define ECC_UTILITY_H

#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <openssl/sha.h>  // OpenSSL for SHA-256
#include <openssl/aes.h>  // OpenSSL for AES encryption
#include <openssl/hmac.h> //OpenSSL for HMAC

// Define the elliptic curve parameters (y^2 = x^3 + ax + b mod p)
typedef struct {
    mpz_t a;  // Coefficient 'a' in the elliptic curve equation
    mpz_t b;  // Coefficient 'b' in the elliptic curve equation
    mpz_t p;  // Prime modulus
    mpz_t n;  // Order of the base point P
} EllipticCurve;

// Define a point on the elliptic curve
typedef struct {
    mpz_t x;  // x-coordinate
    mpz_t y;  // y-coordinate
    int infinity;  // Flag to represent the point at infinity (O)
} Point;

// Initialize a point
void point_init(Point *P) ;

// Free memory allocated for a point
void point_clear(Point *P);

// Check if two points are equal
int point_equals(Point *P1, Point *P2);

// Point addition: P3 = P1 + P2
void point_add(Point *P3, Point *P1, Point *P2, EllipticCurve *curve) ;

// Point doubling: P3 = 2 * P1
void point_double(Point *P3, Point *P1, EllipticCurve *curve) ;

// Scalar multiplication: Q = k * P
void scalar_multiply(Point *Q, Point *P, mpz_t k, EllipticCurve *curve);

#endif
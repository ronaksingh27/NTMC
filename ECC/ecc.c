#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <openssl/sha.h>  // OpenSSL for SHA-256

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
void point_init(Point *P) {
    mpz_init(P->x);
    mpz_init(P->y);
    P->infinity = 0;  // By default, the point is not at infinity
}

// Free memory allocated for a point
void point_clear(Point *P) {
    mpz_clear(P->x);
    mpz_clear(P->y);
}

// Check if two points are equal
int point_equals(Point *P1, Point *P2) {
    if (P1->infinity && P2->infinity) return 1;  // Both points are at infinity
    if (P1->infinity || P2->infinity) return 0;  // One point is at infinity, the other is not
    return (mpz_cmp(P1->x, P2->x) == 0 && (mpz_cmp(P1->y, P2->y) == 0;
}

// Point addition: P3 = P1 + P2
void point_add(Point *P3, Point *P1, Point *P2, EllipticCurve *curve) {
    if (P1->infinity) {
        // If P1 is the point at infinity, P3 = P2
        mpz_set(P3->x, P2->x);
        mpz_set(P3->y, P2->y);
        P3->infinity = P2->infinity;
        return;
    }
    if (P2->infinity) {
        // If P2 is the point at infinity, P3 = P1
        mpz_set(P3->x, P1->x);
        mpz_set(P3->y, P1->y);
        P3->infinity = P1->infinity;
        return;
    }
    if (point_equals(P1, P2)) {
        // If P1 == P2, use point doubling
        point_double(P3, P1, curve);
        return;
    }

    mpz_t lambda, numerator, denominator, temp;
    mpz_inits(lambda, numerator, denominator, temp, NULL);

    // Compute lambda = (y2 - y1) / (x2 - x1) mod p
    mpz_sub(numerator, P2->y, P1->y);
    mpz_sub(denominator, P2->x, P1->x);
    mpz_invert(temp, denominator, curve->p);  // Compute modular inverse
    mpz_mul(lambda, numerator, temp);
    mpz_mod(lambda, lambda, curve->p);

    // Compute x3 = lambda^2 - x1 - x2 mod p
    mpz_mul(temp, lambda, lambda);
    mpz_sub(temp, temp, P1->x);
    mpz_sub(temp, temp, P2->x);
    mpz_mod(P3->x, temp, curve->p);

    // Compute y3 = lambda * (x1 - x3) - y1 mod p
    mpz_sub(temp, P1->x, P3->x);
    mpz_mul(temp, lambda, temp);
    mpz_sub(temp, temp, P1->y);
    mpz_mod(P3->y, temp, curve->p);

    P3->infinity = 0;  // Result is not at infinity

    mpz_clears(lambda, numerator, denominator, temp, NULL);
}

// Point doubling: P3 = 2 * P1
void point_double(Point *P3, Point *P1, EllipticCurve *curve) {
    if (P1->infinity) {
        // If P1 is the point at infinity, P3 is also at infinity
        P3->infinity = 1;
        return;
    }

    mpz_t lambda, numerator, denominator, temp;
    mpz_inits(lambda, numerator, denominator, temp, NULL);

    // Compute lambda = (3 * x1^2 + a) / (2 * y1) mod p
    mpz_mul(temp, P1->x, P1->x);
    mpz_mul_ui(temp, temp, 3);
    mpz_add(temp, temp, curve->a);
    mpz_mul_ui(denominator, P1->y, 2);
    mpz_invert(temp, denominator, curve->p);  // Compute modular inverse
    mpz_mul(lambda, numerator, temp);
    mpz_mod(lambda, lambda, curve->p);

    // Compute x3 = lambda^2 - 2 * x1 mod p
    mpz_mul(temp, lambda, lambda);
    mpz_sub(temp, temp, P1->x);
    mpz_sub(temp, temp, P1->x);
    mpz_mod(P3->x, temp, curve->p);

    // Compute y3 = lambda * (x1 - x3) - y1 mod p
    mpz_sub(temp, P1->x, P3->x);
    mpz_mul(temp, lambda, temp);
    mpz_sub(temp, temp, P1->y);
    mpz_mod(P3->y, temp, curve->p);

    P3->infinity = 0;  // Result is not at infinity

    mpz_clears(lambda, numerator, denominator, temp, NULL);
}

// Scalar multiplication: Q = k * P
void scalar_multiply(Point *Q, Point *P, mpz_t k, EllipticCurve *curve) {
    Point R;
    point_init(&R);
    R.infinity = 1;  // Initialize R as the point at infinity

    for (int i = mpz_sizeinbase(k, 2) - 1; i >= 0; i--) {
        point_double(&R, &R, curve);  // R = 2 * R
        if (mpz_tstbit(k, i)) {
            point_add(&R, &R, P, curve);  // R = R + P
        }
    }

    mpz_set(Q->x, R.x);
    mpz_set(Q->y, R.y);
    Q->infinity = R.infinity;

    point_clear(&R);
}

// System Setup Phase
void system_setup(EllipticCurve *curve, Point *P, mpz_t M_k, Point *P_s) {
    // Define the elliptic curve parameters (example: y^2 = x^3 + 2x + 3 mod 17)
    mpz_init_set_ui(curve->a, 2);
    mpz_init_set_ui(curve->b, 3);
    mpz_init_set_ui(curve->p, 17);
    mpz_init_set_ui(curve->n, 19);  // Order of the base point P

    // Initialize the base point P = (5, 1)
    point_init(P);
    mpz_set_ui(P->x, 5);
    mpz_set_ui(P->y, 1);
    P->infinity = 0;

    // Generate the master key M_k (0 < M_k < n)
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_urandomm(M_k, state, curve->n);  // M_k is a random number < n
    gmp_randclear(state);

    // Compute the public key P_s = M_k * P
    point_init(P_s);
    scalar_multiply(P_s, P, M_k, curve);
}

// Publish the system parameters
void publish_system_parameters(EllipticCurve *curve, Point *P, Point *P_s) {
    printf("Elliptic Curve Parameters:\n");
    printf("a = ");
    mpz_out_str(stdout, 10, curve->a);
    printf("\nb = ");
    mpz_out_str(stdout, 10, curve->b);
    printf("\np = ");
    mpz_out_str(stdout, 10, curve->p);
    printf("\nn = ");
    mpz_out_str(stdout, 10, curve->n);
    printf("\n");

    printf("Base Point P: (");
    mpz_out_str(stdout, 10, P->x);
    printf(", ");
    mpz_out_str(stdout, 10, P->y);
    printf(")\n");

    printf("Public Key P_s: (");
    mpz_out_str(stdout, 10, P_s->x);
    printf(", ");
    mpz_out_str(stdout, 10, P_s->y);
    printf(")\n");
}

// Hash function using OpenSSL's SHA-256
void hash_sha256(const char *input, size_t input_len, unsigned char *output) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, input_len);
    SHA256_Final(output, &sha256);
}

// Registration Phase: Assign private and public keys to a smart meter
void assign_sm_keys(mpz_t SM_pri, Point *SM_pub, mpz_t M_k, Point *P, EllipticCurve *curve, const char *SM_ID) {
    // Compute sigma_j = H(SM_ID) using SHA-256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    hash_sha256(SM_ID, strlen(SM_ID), hash);

    // Convert the hash to an integer (sigma_j)
    mpz_t sigma_j;
    mpz_init(sigma_j);
    mpz_import(sigma_j, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);

    // Compute SM_pri = 1 / (M_k + sigma_j) mod n
    mpz_t temp;
    mpz_init(temp);
    mpz_add(temp, M_k, sigma_j);
    mpz_invert(SM_pri, temp, curve->n);  // SM_pri = 1 / (M_k + sigma_j) mod n

    // Compute SM_pub = (sigma_j + M_k) * P
    mpz_add(temp, sigma_j, M_k);
    scalar_multiply(SM_pub, P, temp, curve);

    mpz_clears(sigma_j, temp, NULL);
}

int main() {
    // Initialize the elliptic curve, base point, master key, and public key
    EllipticCurve curve;
    Point P, P_s;
    mpz_t M_k;
    mpz_init(M_k);

    // Perform the system setup phase
    system_setup(&curve, &P, M_k, &P_s);

    // Publish the system parameters
    publish_system_parameters(&curve, &P, &P_s);

    // Registration Phase: Assign private and public keys to a smart meter
    mpz_t SM_pri;
    mpz_init(SM_pri);
    Point SM_pub;
    point_init(&SM_pub);
    const char *SM_ID = "12345";  // Example SM identity
    assign_sm_keys(SM_pri, &SM_pub, M_k, &P, &curve, SM_ID);

    // Print the SM's private and public keys
    printf("SM Private Key (SM_pri): ");
    mpz_out_str(stdout, 10, SM_pri);
    printf("\nSM Public Key (SM_pub): (");
    mpz_out_str(stdout, 10, SM_pub.x);
    printf(", ");
    mpz_out_str(stdout, 10, SM_pub.y);
    printf(")\n");

    // Clean up
    mpz_clears(curve.a, curve.b, curve.p, curve.n, M_k, SM_pri, NULL);
    point_clear(&P);
    point_clear(&P_s);
    point_clear(&SM_pub);

    return 0;
}
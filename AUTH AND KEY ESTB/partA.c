#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <openssl/sha.h>  // OpenSSL for SHA-256
#include <openssl/aes.h>  // OpenSSL for AES encryption

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


// Check if two points are equal
int point_equals(Point *P1, Point *P2) {
    if (P1->infinity && P2->infinity) return 1;  // Both points are at infinity
    if (P1->infinity || P2->infinity) return 0;  // One point is at infinity, the other is not
    return (mpz_cmp(P1->x, P2->x) == 0) && (mpz_cmp(P1->y, P2->y) == 0);
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

// Hash function using OpenSSL's SHA-256
void hash_sha256(const char *input, size_t input_len, unsigned char *output) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, input_len);
    SHA256_Final(output, &sha256);
}

// AES encryption using OpenSSL
void aes_encrypt(const unsigned char *plaintext, size_t plaintext_len, const unsigned char *key, unsigned char *ciphertext) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);  // 128-bit key
    AES_encrypt(plaintext, ciphertext, &aes_key);
}

// Part (A) of Authentication and Key Establishment Phase
void sm_initiate_authentication(Point *A_SM_j, mpz_t u_SM_j, mpz_t L1, unsigned char *Q1, unsigned char *Y1, mpz_t alpha, mpz_t phi, mpz_t T1,
                                const char *SM_ID_j, const char *N_ID, mpz_t ST_j, mpz_t id_ST_j, Point *P, EllipticCurve *curve) {
    // Step 1: Generate a random number u_SM_j
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_urandomm(u_SM_j, state, curve->n);  // u_SM_j is a random number < n
    gmp_randclear(state);

    // Step 2: Compute A_SM_j = u_SM_j * P
    scalar_multiply(A_SM_j, P, u_SM_j, curve);

    // Step 3: Compute B_SM_j = u_SM_j * SM_pri (not shown here, as SM_pri is not directly used in this part)

    // Step 4: Compute L1 = H(SM_ID_j || N_ID || A_SM_j || B_SM_j || T1)
    char buffer[1024];
    gmp_sprintf(buffer, "%s%s%Zd%Zd%Zd", SM_ID_j, N_ID, A_SM_j->x, A_SM_j->y, T1);  // Concatenate inputs
    unsigned char hash[SHA256_DIGEST_LENGTH];
    hash_sha256(buffer, strlen(buffer), hash);
    mpz_import(L1, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);  // Convert hash to integer

    // Step 5: Compute Q1 = E_ST_j[SM_ID_j, N_ID, T1]
    char plaintext[1024];
    gmp_sprintf(plaintext, "%s%s%Zd", SM_ID_j, N_ID, T1);  // Concatenate inputs
    unsigned char key[16];
    mpz_export(key, NULL, 1, 1, 0, 0, ST_j);  // Use ST_j as the AES key
    aes_encrypt((unsigned char *)plaintext, strlen(plaintext), key, Q1);

    // Step 6: Compute Y1 = MAC_L1[SM_ID_j, T1, A_SM_j]
    char mac_input[1024];
    gmp_sprintf(mac_input, "%s%Zd%Zd%Zd", SM_ID_j, T1, A_SM_j->x, A_SM_j->y);  // Concatenate inputs
    unsigned char mac_hash[SHA256_DIGEST_LENGTH];
    hash_sha256(mac_input, strlen(mac_input), mac_hash);
    memcpy(Y1, mac_hash, SHA256_DIGEST_LENGTH);  // Use hash as MAC

    // Step 7: Compute alpha = H(N_ID || phi) XOR id_ST_j || T1
    char alpha_input[1024];
    gmp_sprintf(alpha_input, "%s%Zd", N_ID, phi);  // Concatenate inputs
    unsigned char alpha_hash[SHA256_DIGEST_LENGTH];
    hash_sha256(alpha_input, strlen(alpha_input), alpha_hash);
    mpz_t alpha_hash_int;
    mpz_init(alpha_hash_int);
    mpz_import(alpha_hash_int, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, alpha_hash);  // Convert hash to integer
    mpz_xor(alpha, alpha_hash_int, id_ST_j);  // XOR with id_ST_j
    mpz_clear(alpha_hash_int);

    // Step 8: Send {alpha, Q1, A_SM_j, Y1, phi, T1} to the NAN Gateway
    printf("SM sends the following message to the NAN Gateway:\n");
    printf("alpha = ");
    mpz_out_str(stdout, 10, alpha);
    printf("\nQ1 = ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) printf("%02x", Q1[i]);
    printf("\nA_SM_j = (");
    mpz_out_str(stdout, 10, A_SM_j->x);
    printf(", ");
    mpz_out_str(stdout, 10, A_SM_j->y);
    printf(")\nY1 = ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", Y1[i]);
    printf("\nphi = ");
    mpz_out_str(stdout, 10, phi);
    printf("\nT1 = ");
    mpz_out_str(stdout, 10, T1);
    printf("\n");
}

int main() {
    // Initialize the elliptic curve, base point, and other parameters
    EllipticCurve curve;
    Point P;
    mpz_init_set_ui(curve.a, 2);
    mpz_init_set_ui(curve.b, 3);
    mpz_init_set_ui(curve.p, 17);
    mpz_init_set_ui(curve.n, 19);
    point_init(&P);
    mpz_set_ui(P.x, 5);
    mpz_set_ui(P.y, 1);

    // Initialize SM_ID_j, N_ID, ST_j, id_ST_j, and T1
    const char *SM_ID_j = "12345";
    const char *N_ID = "NAN1";
    mpz_t ST_j, id_ST_j, T1;
    mpz_init_set_ui(ST_j, 12);  // Example secret token
    mpz_init_set_ui(id_ST_j, 7);  // Example token identifier
    mpz_init_set_ui(T1, 123456789);  // Example timestamp

    // Initialize variables for part (A)
    Point A_SM_j;
    point_init(&A_SM_j);
    mpz_t u_SM_j, L1, alpha, phi;
    mpz_init(u_SM_j);
    mpz_init(L1);
    mpz_init(alpha);
    mpz_init_set_ui(phi, 42);  // Example pseudorandom number
    unsigned char Q1[AES_BLOCK_SIZE];  // AES block size is 16 bytes
    unsigned char Y1[SHA256_DIGEST_LENGTH];  // SHA-256 hash size is 32 bytes

    // Perform part (A) of Authentication and Key Establishment Phase
    sm_initiate_authentication(&A_SM_j, u_SM_j, L1, Q1, Y1, alpha, phi, T1, SM_ID_j, N_ID, ST_j, id_ST_j, &P, &curve);

    // Clean up
    mpz_clears(curve.a, curve.b, curve.p, curve.n, ST_j, id_ST_j, T1, u_SM_j, L1, alpha, phi, NULL);
    point_clear(&P);
    point_clear(&A_SM_j);

    return 0;
}
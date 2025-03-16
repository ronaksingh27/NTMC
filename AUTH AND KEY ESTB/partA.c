#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include "../headers/ecc_utility.h"
#include "../headers/hash_utility.h"
#include "../headers/encrypt_utility.h"

// Part (A) of Authentication and Key Establishment Phase
void sm_initiate_authentication(Point *A_SM_j, mpz_t u_SM_j, mpz_t L1, unsigned char *Q1, unsigned char *Y1, mpz_t alpha, mpz_t phi, mpz_t T1,
    const char *SM_ID_j, const char *N_ID, mpz_t ST_j, mpz_t id_ST_j, mpz_t SM_pri, Point *P, EllipticCurve *curve) {
    // Step 1: Generate a random number u_SM_j
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_urandomm(u_SM_j, state, curve->n);  // u_SM_j is a random number < n
    gmp_randclear(state);

    // Step 2: Compute A_SM_j = u_SM_j * P
    scalar_multiply(A_SM_j, P, u_SM_j, curve);

    // Step 3: Compute B_SM_j = u_SM_j * SM_pri
    mpz_t B_SM_j;
    mpz_init(B_SM_j);
    mpz_mul(B_SM_j, u_SM_j, SM_pri);
    mpz_mod(B_SM_j, B_SM_j, curve->n);  // B_SM_j = u_SM_j * SM_pri mod n

    // Step 4: Compute L1 = H(SM_ID_j || N_ID || A_SM_j || B_SM_j || T1)
    char buffer[1024];
    gmp_sprintf(buffer, "%s%s%Zd%Zd%Zd%Zd", SM_ID_j, N_ID, A_SM_j->x, A_SM_j->y, B_SM_j, T1);  // Concatenate inputs
    unsigned char hash[SHA256_DIGEST_LENGTH];
    hash_sha256(buffer, strlen(buffer), hash);
    mpz_import(L1, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);  // Convert hash to integer

    // Step 5: Compute Q1 = E_ST_j[SM_ID_j, N_ID, T1]
    char plaintext[1024];
    gmp_sprintf(plaintext, "%s%s%Zd", SM_ID_j, N_ID, T1);  // Concatenate inputs
    unsigned char key[16];
    mpz_export(key, NULL, 1, 1, 0, 0, ST_j);  // Use ST_j as the AES key
    aes_encrypt((unsigned char *)plaintext, strlen(plaintext), key, Q1);

    // Step 6: Compute Y1 = HMAC_L1(SM_ID_j || T1 || A_SM_j)
    char mac_input[1024];
    gmp_sprintf(mac_input, "%s%Zd%Zd%Zd", SM_ID_j, T1, A_SM_j->x, A_SM_j->y);  // Concatenate inputs
    unsigned char hmac_key[SHA256_DIGEST_LENGTH];
    mpz_export(hmac_key, NULL, 1, 1, 0, 0, L1);  // Use L1 as the HMAC key
    hmac_sha256(hmac_key, SHA256_DIGEST_LENGTH, (unsigned char *)mac_input, strlen(mac_input), Y1);

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

    mpz_clear(B_SM_j);
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

    // Initialize SM_ID_j, N_ID, ST_j, id_ST_j, T1, and SM_pri
    const char *SM_ID_j = "12345";
    const char *N_ID = "NAN1";
    mpz_t ST_j, id_ST_j, T1, SM_pri;
    mpz_init_set_ui(ST_j, 12);  // Example secret token
    mpz_init_set_ui(id_ST_j, 7);  // Example token identifier
    mpz_init_set_ui(T1, 123456789);  // Example timestamp
    mpz_init_set_ui(SM_pri, 17);  // Example SM private key

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
    sm_initiate_authentication(&A_SM_j, u_SM_j, L1, Q1, Y1, alpha, phi, T1, SM_ID_j, N_ID, ST_j, id_ST_j, SM_pri, &P, &curve);

    // Clean up
    mpz_clears(curve.a, curve.b, curve.p, curve.n, ST_j, id_ST_j, T1, SM_pri, u_SM_j, L1, alpha, phi, NULL);
    point_clear(&P);
    point_clear(&A_SM_j);

    return 0;
}
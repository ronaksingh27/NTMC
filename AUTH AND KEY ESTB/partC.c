#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include "../headers/ecc_utility.h"
#include "../headers/hash_utility.h"
#include "../headers/encrypt_utility.h"

void nan_respond_to_sm(const char *SM_ID_j, const char *N_ID, mpz_t ST_j, mpz_t id_ST_j, mpz_t T2, Point *A_SM_j, mpz_t L1_prime, EllipticCurve *curve, Point *P) {
    // Step 1: Generate a random number v_N
    mpz_t v_N;
    mpz_init(v_N);
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_urandomm(v_N, state, curve->n);  // v_N < n
    gmp_randclear(state);

    // Step 2: Compute C_N = v_N * P
    Point C_N;
    point_init(&C_N);
    scalar_multiply(&C_N, P, v_N, curve);

    // Step 3: Compute F_N = v_N * A_SM_j
    Point F_N;
    point_init(&F_N);
    scalar_multiply(&F_N, A_SM_j, v_N, curve);

    // Step 4: Compute Q2 = E_ST_j[SM_ID_j, N_ID, T2]
    char plaintext[1024];
    gmp_sprintf(plaintext, "%s%s%Zd", SM_ID_j, N_ID, T2);
    unsigned char key[16];
    mpz_export(key, NULL, 1, 1, 0, 0, ST_j);  // Use ST_j as AES key
    unsigned char Q2[AES_BLOCK_SIZE];
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    AES_encrypt((unsigned char *)plaintext, Q2, &aes_key);

    // Step 5: Compute Y2 = MAC_L1'[N_ID, T2, C_N]
    char mac_input[1024];
    gmp_sprintf(mac_input, "%s%Zd%Zd%Zd", N_ID, T2, C_N.x, C_N.y);
    unsigned char Y2[SHA256_DIGEST_LENGTH];
    hash_sha256(mac_input, strlen(mac_input), Y2);

    // Step 6: Generate session key SK = H(SM_ID_j || N_ID || A_SM_j || C_N || F_N)
    char sk_input[1024];
    gmp_sprintf(sk_input, "%s%s%Zd%Zd%Zd%Zd%Zd%Zd", SM_ID_j, N_ID, A_SM_j->x, A_SM_j->y, C_N.x, C_N.y, F_N.x, F_N.y);
    unsigned char SK_hash[SHA256_DIGEST_LENGTH];
    hash_sha256(sk_input, strlen(sk_input), SK_hash);
    printf("Session Key SK: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", SK_hash[i]);
    printf("\n");

    // Step 7: Compute β = H(N_ID || ϕ_N) XOR id_ST_j || T2
    mpz_t phi_N, beta;
    mpz_init(phi_N);
    mpz_init(beta);
    gmp_randinit_default(state);
    mpz_urandomm(phi_N, state, curve->n);  // Random ϕ_N
    gmp_randclear(state);

    char beta_input[1024];
    gmp_sprintf(beta_input, "%s%Zd", N_ID, phi_N);
    unsigned char beta_hash[SHA256_DIGEST_LENGTH];
    hash_sha256(beta_input, strlen(beta_input), beta_hash);
    mpz_t beta_hash_int;
    mpz_init(beta_hash_int);
    mpz_import(beta_hash_int, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, beta_hash);
    mpz_xor(beta, beta_hash_int, id_ST_j);  // β = H(N_ID || ϕ_N) XOR id_ST_j
    mpz_clear(beta_hash_int);

    // Step 8: Send {β, C_N, Q2, Y2, ϕ_N, T2} to the SM
    printf("NAN Gateway sends the following response to the SM:\n");
    printf("β = ");
    mpz_out_str(stdout, 10, beta);
    printf("\nC_N = (");
    mpz_out_str(stdout, 10, C_N.x);
    printf(", ");
    mpz_out_str(stdout, 10, C_N.y);
    printf(")\nQ2 = ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) printf("%02x", Q2[i]);
    printf("\nY2 = ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", Y2[i]);
    printf("\nϕ_N = ");
    mpz_out_str(stdout, 10, phi_N);
    printf("\nT2 = ");
    mpz_out_str(stdout, 10, T2);
    printf("\n");

    // Clean up
    mpz_clears(v_N, phi_N, beta, NULL);
    point_clear(&C_N);
    point_clear(&F_N);
}

int main() {
    // Initialize parameters (same as before)
    EllipticCurve curve;
    Point P;
    mpz_init_set_ui(curve.a, 2);
    mpz_init_set_ui(curve.b, 3);
    mpz_init_set_ui(curve.p, 17);
    mpz_init_set_ui(curve.n, 19);
    point_init(&P);
    mpz_set_ui(P.x, 5);
    mpz_set_ui(P.y, 1);

    const char *SM_ID_j = "12345";
    const char *N_ID = "NAN1";
    mpz_t ST_j, id_ST_j, T2, L1_prime;
    mpz_init_set_ui(ST_j, 12);
    mpz_init_set_ui(id_ST_j, 7);
    mpz_init_set_ui(T2, 123456799);
    mpz_init_set_ui(L1_prime, 42);  // Example L1' (hash from part B)

    Point A_SM_j;
    point_init(&A_SM_j);
    mpz_set_ui(A_SM_j.x, 10);
    mpz_set_ui(A_SM_j.y, 6);

    // Perform part (C) of Authentication and Key Establishment Phase
    nan_respond_to_sm(SM_ID_j, N_ID, ST_j, id_ST_j, T2, &A_SM_j, L1_prime, &curve, &P);

    // Clean up
    mpz_clears(curve.a, curve.b, curve.p, curve.n, ST_j, id_ST_j, T2, L1_prime, NULL);
    point_clear(&P);
    point_clear(&A_SM_j);

    return 0;
}
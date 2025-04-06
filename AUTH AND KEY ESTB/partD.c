#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include "../headers/ecc_utility.h"
#include "../headers/hash_utility.h"
#include "../headers/encrypt_utility.h"

void sm_verify_response(const char *SM_ID_j, const char *N_ID, mpz_t ST_j, mpz_t id_ST_j, mpz_t T2, mpz_t T3, mpz_t beta, unsigned char *Q2, Point *C_N, unsigned char *Y2, mpz_t phi_N, Point *A_SM_j, mpz_t u_SM_j, EllipticCurve *curve) {
    // Step 1: Check timestamp validity (T3 - T2 <= ΔT)
    mpz_t delta_T;
    mpz_init_set_ui(delta_T, 10);  // ΔT = 10 seconds
    mpz_t time_diff;
    mpz_init(time_diff);
    mpz_sub(time_diff, T3, T2);
    if (mpz_cmp(time_diff, delta_T) > 0) {
        printf("Error: Timestamp validation failed (replay attack detected).\n");
        mpz_clears(delta_T, time_diff, NULL);
        return;
    }
    mpz_clears(delta_T, time_diff, NULL);

    // Step 2: Retrieve id_ST_j from β = H(N_ID || ϕ_N) XOR id_ST_j || T2
    mpz_t H_NID_phiN;
    mpz_init(H_NID_phiN);
    char buffer[1024];
    gmp_sprintf(buffer, "%s%Zd", N_ID, phi_N);  // N_ID || ϕ_N
    unsigned char hash[SHA256_DIGEST_LENGTH];
    hash_sha256(buffer, strlen(buffer), hash);
    mpz_import(H_NID_phiN, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);
    mpz_t recovered_id_ST_j;
    mpz_init(recovered_id_ST_j);
    mpz_xor(recovered_id_ST_j, beta, H_NID_phiN);  // XOR to recover id_ST_j
    mpz_clear(H_NID_phiN);

    printf("Recovered id_ST_j: ");
    mpz_out_str(stdout, 10, recovered_id_ST_j);
    printf("\n");

    // Step 3: Retrieve ST_j from the database (simplified here)
    // In practice, use `recovered_id_ST_j` to fetch ST_j from a database.
    // For this example, we assume ST_j is already known.

    // Step 4: Decrypt Q2 = E_ST_j[SM_ID_j, N_ID, T2]
    unsigned char key[16];
    mpz_export(key, NULL, 1, 1, 0, 0, ST_j);  // Convert ST_j to AES key
    unsigned char decrypted[AES_BLOCK_SIZE + 1] = {0};  // +1 for null terminator
    aes_decrypt(Q2, AES_BLOCK_SIZE, key, decrypted);
    decrypted[AES_BLOCK_SIZE] = '\0';  // Null-terminate for string comparison

    printf("Decrypted Q2: %u\n", decrypted);

    // Step 5: Verify decrypted Q2 matches expected format
    char expected_Q2[1024];
    gmp_sprintf(expected_Q2, "%s%s%Zd", SM_ID_j, N_ID, T2);
    if (strcmp((char *)decrypted, expected_Q2) != 0) {
        printf("Error: Decrypted Q2 does not match expected values.\n");
        printf("Expected: %s\n", expected_Q2);
        printf("Actual: %u\n", decrypted);
        mpz_clear(recovered_id_ST_j);
        return;
    }

    // Step 6: Verify Y2 (MAC)
    char L1_prime_input[1024];
    gmp_sprintf(L1_prime_input, "%s%s%Zd%Zd%Zd", SM_ID_j, N_ID, A_SM_j->x, A_SM_j->y, T2);  // L1' from part (B)
    unsigned char L1_prime_hash[SHA256_DIGEST_LENGTH];
    hash_sha256(L1_prime_input, strlen(L1_prime_input), L1_prime_hash);

    char mac_input[1024];
    gmp_sprintf(mac_input, "%s%Zd%Zd%Zd", N_ID, T2, C_N->x, C_N->y);
    unsigned char computed_Y2[SHA256_DIGEST_LENGTH];
    hash_sha256(mac_input, strlen(mac_input), computed_Y2);

    if (memcmp(Y2, computed_Y2, SHA256_DIGEST_LENGTH) != 0) {
        printf("Error: MAC verification failed.\n");
        mpz_clear(recovered_id_ST_j);
        return;
    }

    // Step 7: Compute W_SM_j = u_SM_j * C_N
    Point W_SM_j;
    point_init(&W_SM_j);
    scalar_multiply(&W_SM_j, C_N, u_SM_j, curve);

    // Step 8: Generate session key SK = H(SM_ID_j || N_ID || A_SM_j || C_N || W_SM_j)
    char sk_input[1024];
    gmp_sprintf(sk_input, "%s%s%Zd%Zd%Zd%Zd%Zd%Zd", SM_ID_j, N_ID, A_SM_j->x, A_SM_j->y, C_N->x, C_N->y, W_SM_j.x, W_SM_j.y);
    unsigned char SK_hash[SHA256_DIGEST_LENGTH];
    hash_sha256(sk_input, strlen(sk_input), SK_hash);

    printf("Session Key SK: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", SK_hash[i]);
    printf("\n");

    printf("Authentication successful. Secure session established.\n");

    // Clean up
    mpz_clear(recovered_id_ST_j);
    point_clear(&W_SM_j);
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
    mpz_t ST_j, id_ST_j, T2, T3, beta, phi_N, u_SM_j;
    mpz_init_set_ui(ST_j, 12);
    mpz_init_set_ui(id_ST_j, 7);
    mpz_init_set_ui(T2, 123456799);
    mpz_init_set_ui(T3, 123456809);  // Current timestamp at SM
    mpz_init_set_ui(beta, 42);       // Example β from NAN Gateway
    mpz_init_set_ui(phi_N, 42);      // Example ϕ_N from NAN Gateway
    mpz_init_set_ui(u_SM_j, 8);      // Example u_SM_j from part (A)

    // Simulate received message {β, C_N, Q2, Y2, ϕ_N, T2} from NAN Gateway
    Point C_N;
    point_init(&C_N);
    mpz_set_ui(C_N.x, 15);
    mpz_set_ui(C_N.y, 8);

    unsigned char Q2[AES_BLOCK_SIZE] = {0x5a, 0x1f, 0x3e, 0x4d, 0x2c, 0x6b, 0x8a, 0x9e, 0x00};  // Example encrypted Q2
    unsigned char Y2[SHA256_DIGEST_LENGTH] = {0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b, 0x00};  // Example MAC Y2

    Point A_SM_j;
    point_init(&A_SM_j);
    mpz_set_ui(A_SM_j.x, 10);
    mpz_set_ui(A_SM_j.y, 6);

    // Perform part (D) of Authentication and Key Establishment Phase
    sm_verify_response(SM_ID_j, N_ID, ST_j, id_ST_j, T2, T3, beta, Q2, &C_N, Y2, phi_N, &A_SM_j, u_SM_j, &curve);

    // Clean up
    mpz_clears(curve.a, curve.b, curve.p, curve.n, ST_j, id_ST_j, T2, T3, beta, phi_N, u_SM_j, NULL);
    point_clear(&P);
    point_clear(&C_N);
    point_clear(&A_SM_j);

    return 0;
}
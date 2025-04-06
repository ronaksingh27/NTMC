#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include "../headers/ecc_utility.h"
#include "../headers/hash_utility.h"
#include "../headers/encrypt_utility.h"

void nan_verify_authentication(const char *SM_ID_j, const char *N_ID, mpz_t M_k, mpz_t ST_j, mpz_t id_ST_j, mpz_t T1, mpz_t T2, mpz_t alpha, unsigned char *Q1, Point *A_SM_j, unsigned char *Y1, mpz_t phi, EllipticCurve *curve, Point *P_s) {
    // Step 1: Check timestamp validity (T2 - T1 <= ΔT)
    mpz_t delta_T;
    mpz_init_set_ui(delta_T, 10);  // ΔT = 10 seconds
    mpz_t time_diff;
    mpz_init(time_diff);
    mpz_sub(time_diff, T2, T1);
    if (mpz_cmp(time_diff, delta_T) > 0) {
        printf("Error: Timestamp validation failed (replay attack detected).\n");
        mpz_clears(delta_T, time_diff, NULL);
        return;
    }
    mpz_clears(delta_T, time_diff, NULL);

    // Step 2: Retrieve id_ST_j from α = H(N_ID || ϕ) XOR id_ST_j || T1
    mpz_t H_NID_phi;
    mpz_init(H_NID_phi);
    char buffer[1024];
    gmp_sprintf(buffer, "%s%Zd", N_ID, phi);  // N_ID || ϕ
    unsigned char hash[SHA256_DIGEST_LENGTH];
    hash_sha256(buffer, strlen(buffer), hash);
    mpz_import(H_NID_phi, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);
    mpz_t recovered_id_ST_j;
    mpz_init(recovered_id_ST_j);
    mpz_xor(recovered_id_ST_j, alpha, H_NID_phi);  // XOR to recover id_ST_j
    mpz_clear(H_NID_phi);

    printf("Recovered id_ST_j: ");
    mpz_out_str(stdout, 10, recovered_id_ST_j);
    printf("\n");

    // Step 3: Retrieve ST_j from the database (simplified here)
    // In practice, use `recovered_id_ST_j` to fetch ST_j from a database.
    // For this example, we assume ST_j is already known.

    // Step 4: Decrypt Q1 = E_ST_j[SM_ID_j, N_ID, T1]
    unsigned char key[16];
    mpz_export(key, NULL, 1, 1, 0, 0, ST_j);  // Convert ST_j to AES key
    unsigned char decrypted[AES_BLOCK_SIZE + 1] = {0};  // +1 for null terminator
    aes_decrypt(Q1, AES_BLOCK_SIZE, key, decrypted);
    decrypted[AES_BLOCK_SIZE] = '\0';  // Null-terminate for string comparison

    printf("Decrypted Q1: %u\n", decrypted);

    // Step 5: Verify decrypted Q1 matches expected format
    char expected_Q1[1024];
    gmp_sprintf(expected_Q1, "%s%s%Zd", SM_ID_j, N_ID, T1);
    if (strcmp((char *)decrypted, expected_Q1) != 0) {
        printf("Error: Decrypted Q1 does not match expected values.\n");
        printf("Expected: %s\n", expected_Q1);
        printf("Actual: %u\n", decrypted);
        mpz_clear(recovered_id_ST_j);
        return;
    }

    // Step 6: Compute σ_j' = H(SM_ID_j)
    mpz_t sigma_j_prime;
    mpz_init(sigma_j_prime);
    unsigned char sigma_hash[SHA256_DIGEST_LENGTH];
    hash_sha256(SM_ID_j, strlen(SM_ID_j), sigma_hash);
    mpz_import(sigma_j_prime, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, sigma_hash);
    printf("σ_j' (H(SM_ID_j)): ");
    mpz_out_str(stdout, 10, sigma_j_prime);
    printf("\n");

    // Step 7: Compute B_SM_j' = (1 / (M_k + σ_j')) * A_SM_j
    mpz_t denominator;
    mpz_init(denominator);
    mpz_add(denominator, M_k, sigma_j_prime);  // M_k + σ_j'
    mpz_t inv_denominator;
    mpz_init(inv_denominator);
    mpz_invert(inv_denominator, denominator, curve->n);  // 1 / (M_k + σ_j') mod n

    Point B_SM_j_prime;
    point_init(&B_SM_j_prime);
    scalar_multiply(&B_SM_j_prime, A_SM_j, inv_denominator, curve);  // B_SM_j' = inv_denominator * A_SM_j

    printf("B_SM_j': (");
    mpz_out_str(stdout, 10, B_SM_j_prime.x);
    printf(", ");
    mpz_out_str(stdout, 10, B_SM_j_prime.y);
    printf(")\n");

    // Step 8: Verify Y1 (MAC)
    char L1_input[1024];
    gmp_sprintf(L1_input, "%s%s%Zd%Zd%Zd", SM_ID_j, N_ID, A_SM_j->x, A_SM_j->y, T1);
    unsigned char computed_Y1[SHA256_DIGEST_LENGTH];
    hash_sha256(L1_input, strlen(L1_input), computed_Y1);

    if (memcmp(Y1, computed_Y1, SHA256_DIGEST_LENGTH) != 0) {
        printf("Error: MAC verification failed.\n");
        mpz_clears(sigma_j_prime, denominator, inv_denominator, recovered_id_ST_j, NULL);
        point_clear(&B_SM_j_prime);
        return;
    }

    printf("Authentication successful. Session key generation pending.\n");

    // Clean up
    mpz_clears(sigma_j_prime, denominator, inv_denominator, recovered_id_ST_j, NULL);
    point_clear(&B_SM_j_prime);
}

int main() {
    // Initialize parameters (same as before)
    EllipticCurve curve;
    Point P, P_s;
    mpz_init_set_ui(curve.a, 2);
    mpz_init_set_ui(curve.b, 3);
    mpz_init_set_ui(curve.p, 17);
    mpz_init_set_ui(curve.n, 19);
    point_init(&P);
    mpz_set_ui(P.x, 5);
    mpz_set_ui(P.y, 1);
    point_init(&P_s);
    mpz_set_ui(P_s.x, 6);
    mpz_set_ui(P_s.y, 3);

    const char *SM_ID_j = "12345";
    const char *N_ID = "NAN1";
    mpz_t M_k, ST_j, id_ST_j, T1, T2, alpha, phi;
    mpz_init_set_ui(M_k, 5);  // Example master key
    mpz_init_set_ui(ST_j, 12);
    mpz_init_set_ui(id_ST_j, 7);
    mpz_init_set_ui(T1, 123456789);
    mpz_init_set_ui(T2, 123456799);
    mpz_init_set_ui(alpha, 42);
    mpz_init_set_ui(phi, 42);

    // Simulate Q1 (must match the encryption in part (A))
    unsigned char Q1[AES_BLOCK_SIZE];
    char plaintext[1024];
    gmp_sprintf(plaintext, "%s%s%Zd", SM_ID_j, N_ID, T1);
    unsigned char key[16];
    mpz_export(key, NULL, 1, 1, 0, 0, ST_j);
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    AES_encrypt((unsigned char *)plaintext, Q1, &aes_key);  // Correct Q1

    Point A_SM_j;
    point_init(&A_SM_j);
    mpz_set_ui(A_SM_j.x, 10);
    mpz_set_ui(A_SM_j.y, 6);

    // Simulate Y1 (must match the MAC computation in part (A))
    unsigned char Y1[SHA256_DIGEST_LENGTH];
    char mac_input[1024];
    gmp_sprintf(mac_input, "%s%Zd%Zd%Zd", SM_ID_j, T1, A_SM_j.x, A_SM_j.y);
    hash_sha256(mac_input, strlen(mac_input), Y1);

    nan_verify_authentication(SM_ID_j, N_ID, M_k, ST_j, id_ST_j, T1, T2, alpha, Q1, &A_SM_j, Y1, phi, &curve, &P_s);

    // Clean up
    mpz_clears(curve.a, curve.b, curve.p, curve.n, M_k, ST_j, id_ST_j, T1, T2, alpha, phi, NULL);
    point_clear(&P);
    point_clear(&P_s);
    point_clear(&A_SM_j);

    return 0;
}
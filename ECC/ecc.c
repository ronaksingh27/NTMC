#include <stdio.h>
#include <gmp.h>
#include <string.h>

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
void assign_sm_keys(mpz_t SM_pri, Point *SM_pub, mpz_t M_k, Point *P, EllipticCurve *curve, const char *SM_ID, mpz_t ST_j, mpz_t id_ST_j) {
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

    // Generate the secret token ST_j and its identifier id_ST_j
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_urandomm(ST_j, state, curve->n);  // ST_j is a random number < n
    mpz_urandomm(id_ST_j, state, curve->n);  // id_ST_j is a random number < n
    gmp_randclear(state);

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

    // Initialize the secret token ST_j and its identifier id_ST_j
    mpz_t ST_j, id_ST_j;
    mpz_init(ST_j);
    mpz_init(id_ST_j);

    // Assign keys and generate the secret token
    assign_sm_keys(SM_pri, &SM_pub, M_k, &P, &curve, SM_ID, ST_j, id_ST_j);

    // Print the SM's private and public keys
    printf("SM Private Key (SM_pri): ");
    mpz_out_str(stdout, 10, SM_pri);
    printf("\nSM Public Key (SM_pub): (");
    mpz_out_str(stdout, 10, SM_pub.x);
    printf(", ");
    mpz_out_str(stdout, 10, SM_pub.y);
    printf(")\n");

    // Print the secret token and its identifier
    printf("Secret Token (ST_j): ");
    mpz_out_str(stdout, 10, ST_j);
    printf("\nToken Identifier (id_ST_j): ");
    mpz_out_str(stdout, 10, id_ST_j);
    printf("\n");

    // Clean up
    mpz_clears(curve.a, curve.b, curve.p, curve.n, M_k, SM_pri, ST_j, id_ST_j, NULL);
    point_clear(&P);
    point_clear(&P_s);
    point_clear(&SM_pub);

    return 0;
}

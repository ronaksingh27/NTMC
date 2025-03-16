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
    return (mpz_cmp(P1->x, P2->x) == 0) && (mpz_cmp(P1->y, P2->y) == 0);
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


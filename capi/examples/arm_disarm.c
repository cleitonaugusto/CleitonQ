/*
 * CleitonQ C API — Example: ARM/DISARM command authentication
 *
 * Demonstrates a complete ground station → drone authentication flow:
 *   1. ML-KEM-1024 session key establishment (forward secrecy)
 *   2. HMAC-SHA3-256 channel authentication (continuous traffic)
 *   3. ML-DSA-87 command signing (ARM_DISARM non-repudiation)
 *
 * Compile via CMake:
 *   cmake -B build && cmake --build build
 *   ./build/arm_disarm
 *
 * Reference: https://github.com/cleitonaugusto/CleitonQ
 * IETF I-D:  https://datatracker.ietf.org/doc/draft-bezerra-relay-auth-transparency/
 */

#include <cleitonq.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static void die(const char *msg, int code) {
    fprintf(stderr, "FAIL: %s (code %d)\n", msg, code);
    exit(1);
}

/* ── Step 1: KEM handshake ─────────────────────────────────────────────────── */

static void demo_kem_handshake(void) {
    printf("\n=== Step 1: ML-KEM-1024 session key establishment ===\n");

    /* DRONE: generate key pair */
    cleitonq_kem_keypair_t *drone_kp = cleitonq_kem_keygen();
    if (!drone_kp) die("keygen failed", 0);

    uint8_t ek[CLEITONQ_KEM_EK_BYTES];        /* drone sends this to GCS */
    uint8_t dk_seed[CLEITONQ_KEM_DK_SEED_BYTES]; /* drone keeps this secret */

    int rc = cleitonq_kem_ek_bytes(drone_kp, ek, sizeof(ek));
    if (rc != CLEITONQ_OK) die("ek_bytes", rc);

    rc = cleitonq_kem_dk_seed(drone_kp, dk_seed, sizeof(dk_seed));
    if (rc != CLEITONQ_OK) die("dk_seed", rc);

    cleitonq_kem_keypair_free(drone_kp);
    printf("  Drone generated KEM keypair (EK: %zu bytes, DK seed: %zu bytes)\n",
           sizeof(ek), sizeof(dk_seed));

    /* GCS: encapsulate session key using drone's EK */
    uint8_t ct[CLEITONQ_KEM_CT_BYTES];  /* GCS sends ciphertext to drone */
    uint8_t ss_gcs[CLEITONQ_KEM_SS_BYTES];

    rc = cleitonq_kem_encapsulate(ek, ct, ss_gcs);
    if (rc != CLEITONQ_OK) die("encapsulate", rc);
    printf("  GCS encapsulated session key (ciphertext: %zu bytes)\n", sizeof(ct));

    /* DRONE: decapsulate → recover same session key */
    uint8_t ss_drone[CLEITONQ_KEM_SS_BYTES];

    rc = cleitonq_kem_decapsulate(dk_seed, ct, ss_drone);
    if (rc != CLEITONQ_OK) die("decapsulate", rc);
    printf("  Drone decapsulated session key\n");

    /* Both sides must have the same 32-byte secret */
    assert(memcmp(ss_gcs, ss_drone, CLEITONQ_KEM_SS_BYTES) == 0);
    printf("  Session keys match: OK\n");

    /* ── Step 2: AuthChannel (HMAC) ─────────────────────────────────────── */
    printf("\n=== Step 2: AuthChannel — continuous telemetry (HMAC-SHA3-256) ===\n");

    cleitonq_channel_t *gcs_ch = cleitonq_channel_new(ss_gcs, CLEITONQ_DOMAIN_C2);
    cleitonq_channel_t *drone_ch = cleitonq_channel_new(ss_drone, CLEITONQ_DOMAIN_C2);
    if (!gcs_ch || !drone_ch) die("channel_new", 0);

    /* Simulate a stream of telemetry/C2 commands */
    const char *commands[] = {
        "SET_MODE mode=AUTO",
        "GOTO_WAYPOINT lat=10.0 lon=20.0 alt=100.0",
        "ARM_DISARM arm=1",
    };
    uint64_t last_nonce = 0;

    for (int i = 0; i < 3; i++) {
        const uint8_t *cmd = (const uint8_t *)commands[i];
        size_t cmd_len = strlen(commands[i]);
        size_t packet_cap = cmd_len + CLEITONQ_CHANNEL_OVERHEAD;
        uint8_t *packet = malloc(packet_cap);

        /* GCS signs with nonce i+1 */
        int pkt_len = cleitonq_channel_sign(gcs_ch, cmd, cmd_len,
                                             (uint64_t)(i + 1), packet, packet_cap);
        if (pkt_len < 0) die("channel_sign", pkt_len);

        /* Drone verifies */
        uint8_t payload[256];
        uint64_t nonce;
        int pl_len = cleitonq_channel_verify(drone_ch, packet, (size_t)pkt_len,
                                              last_nonce, payload, sizeof(payload), &nonce);
        if (pl_len < 0) die("channel_verify", pl_len);

        last_nonce = nonce;
        payload[pl_len] = '\0';
        printf("  [nonce=%llu] %s → OK (%d wire bytes)\n",
               (unsigned long long)nonce, (char *)payload, pkt_len);
        free(packet);
    }

    /* Replay attack — must be rejected */
    {
        const char *cmd = "ARM_DISARM arm=1";
        size_t cmd_len = strlen(cmd);
        uint8_t packet[64 + CLEITONQ_CHANNEL_OVERHEAD];
        cleitonq_channel_sign(gcs_ch, (const uint8_t *)cmd, cmd_len,
                               1, packet, sizeof(packet)); /* nonce=1, already seen */
        rc = cleitonq_channel_verify(drone_ch, packet, cmd_len + CLEITONQ_CHANNEL_OVERHEAD,
                                     last_nonce, NULL, 0, NULL);
        assert(rc == CLEITONQ_ERR_VERIFY);
        printf("  Replay (nonce=1, last=%llu): REJECTED — OK\n",
               (unsigned long long)last_nonce);
    }

    cleitonq_channel_free(gcs_ch);
    cleitonq_channel_free(drone_ch);

    /* ── Step 3: ML-DSA-87 signing for critical commands ────────────────── */
    printf("\n=== Step 3: ML-DSA-87 — ARM_DISARM with non-repudiation ===\n");

    cleitonq_signing_key_t *gcs_sk = cleitonq_dsa_keygen();
    cleitonq_verifying_key_t *drone_vk = cleitonq_dsa_verifying_key(gcs_sk);
    if (!gcs_sk || !drone_vk) die("dsa keygen", 0);

    /* Export VK bytes — this is what ships inside each drone at ceremony */
    uint8_t vk_bytes[CLEITONQ_DSA_VK_BYTES];
    rc = cleitonq_dsa_vk_to_bytes(drone_vk, vk_bytes);
    if (rc != CLEITONQ_OK) die("vk_to_bytes", rc);
    printf("  GCS signing key generated (VK: %d bytes, sent to all drones)\n",
           CLEITONQ_DSA_VK_BYTES);

    /* GCS signs the ARM command */
    const char *arm_cmd = "ARM_DISARM arm=1 force=0";
    size_t arm_len = strlen(arm_cmd);
    size_t pkt_cap = arm_len + CLEITONQ_DSA_OVERHEAD;
    uint8_t *arm_pkt = malloc(pkt_cap);

    int pkt_len = cleitonq_dsa_sign(gcs_sk, (const uint8_t *)arm_cmd, arm_len,
                                     42, arm_pkt, pkt_cap);
    if (pkt_len < 0) die("dsa_sign", pkt_len);
    printf("  ARM_DISARM signed: %d wire bytes (payload=%zu + overhead=%d)\n",
           pkt_len, arm_len, CLEITONQ_DSA_OVERHEAD);

    /* Reconstruct VK from bytes (as drone would from its flash) */
    cleitonq_verifying_key_t *vk2 = cleitonq_dsa_vk_from_bytes(vk_bytes);
    if (!vk2) die("vk_from_bytes", 0);

    /* Drone verifies */
    uint8_t recovered[256];
    uint64_t cmd_nonce;
    int pl_len = cleitonq_dsa_verify(vk2, arm_pkt, (size_t)pkt_len,
                                      0, recovered, sizeof(recovered), &cmd_nonce);
    if (pl_len < 0) die("dsa_verify", pl_len);
    recovered[pl_len] = '\0';

    printf("  Drone verified: \"%s\" (nonce=%llu) — OK\n",
           recovered, (unsigned long long)cmd_nonce);

    /* Tamper test */
    arm_pkt[0] ^= 0xFF;
    rc = cleitonq_dsa_verify(vk2, arm_pkt, (size_t)pkt_len, 0, NULL, 0, NULL);
    assert(rc == CLEITONQ_ERR_VERIFY);
    printf("  Tampered command: REJECTED — OK\n");

    free(arm_pkt);
    cleitonq_dsa_sk_free(gcs_sk);
    cleitonq_dsa_vk_free(drone_vk);
    cleitonq_dsa_vk_free(vk2);

    printf("\n=== All checks passed. CleitonQ v%s ===\n", cleitonq_version());
}

int main(void) {
    demo_kem_handshake();
    return 0;
}

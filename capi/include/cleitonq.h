/*
 * CleitonQ C API — Post-quantum authentication for autonomous systems
 * Copyright (c) 2026 Cleiton Augusto Correa Bezerra. MIT OR Apache-2.0.
 *
 * Algorithms: ML-KEM-1024 (FIPS 203), ML-DSA-87 (FIPS 204), HMAC-SHA3-256 (FIPS 202)
 * Reference:  https://github.com/cleitonaugusto/CleitonQ
 * IETF I-D:   https://datatracker.ietf.org/doc/draft-bezerra-relay-auth-transparency/
 */

#ifndef CLEITONQ_H
#define CLEITONQ_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Error codes ──────────────────────────────────────────────────────────── */

#define CLEITONQ_OK            0   /**< Operation succeeded.                  */
#define CLEITONQ_ERR_NULL     -1   /**< Required pointer was null.            */
#define CLEITONQ_ERR_VERIFY   -2   /**< Authentication/signature invalid.     */
#define CLEITONQ_ERR_BUFFER   -3   /**< Output buffer too small.              */
#define CLEITONQ_ERR_INVALID  -4   /**< Invalid key, seed, or argument.       */

/* ── Wire format constants ────────────────────────────────────────────────── */

/** AuthChannel overhead per packet: 8-byte nonce + 32-byte HMAC-SHA3-256 tag. */
#define CLEITONQ_CHANNEL_OVERHEAD   40

/** ML-DSA-87 signature size (FIPS 204, Table 1). */
#define CLEITONQ_DSA_SIG_BYTES      4627

/** ML-DSA-87 packet overhead: 8-byte nonce + signature. */
#define CLEITONQ_DSA_OVERHEAD       4635

/** ML-DSA-87 verifying key size in bytes. */
#define CLEITONQ_DSA_VK_BYTES       2592

/** ML-DSA-87 signing key seed size (32 bytes reconstruct the full key). */
#define CLEITONQ_DSA_SK_SEED_BYTES  32

/** ML-KEM-1024 encapsulation key size (public, share with ground station). */
#define CLEITONQ_KEM_EK_BYTES       1568

/** ML-KEM-1024 ciphertext size. */
#define CLEITONQ_KEM_CT_BYTES       1568

/** ML-KEM-1024 decapsulation key seed size (private, keep on drone). */
#define CLEITONQ_KEM_DK_SEED_BYTES  64

/** ML-KEM-1024 shared session key size. */
#define CLEITONQ_KEM_SS_BYTES       32

/* ── Channel domain labels ────────────────────────────────────────────────── */

#define CLEITONQ_DOMAIN_C2          0  /**< Inbound C2 (GCS → drone).         */
#define CLEITONQ_DOMAIN_TELEMETRY   1  /**< Outbound telemetry (drone → GCS). */
#define CLEITONQ_DOMAIN_MESH        2  /**< Inter-drone mesh.                  */

/* ── Opaque types ─────────────────────────────────────────────────────────── */

/** Authenticated channel (HMAC-SHA3-256). */
typedef struct cleitonq_channel   cleitonq_channel_t;

/** ML-DSA-87 signing key (private — ground station only). */
typedef struct cleitonq_signing_key   cleitonq_signing_key_t;

/** ML-DSA-87 verifying key (public — distribute to drones). */
typedef struct cleitonq_verifying_key cleitonq_verifying_key_t;

/** ML-KEM-1024 key pair (generate on drone, export EK to GCS). */
typedef struct cleitonq_kem_keypair   cleitonq_kem_keypair_t;

/* ── Version ──────────────────────────────────────────────────────────────── */

/**
 * Returns the CleitonQ library version as a null-terminated string.
 * The pointer is valid for the lifetime of the process.
 */
const char *cleitonq_version(void);

/* ── AuthChannel ──────────────────────────────────────────────────────────── */
/*
 * Authenticated channel using HMAC-SHA3-256 with a 32-byte session key.
 * Provides per-packet integrity, anti-replay, and domain separation.
 *
 * Use for: all continuous telemetry and heartbeat traffic (< 0.1 ms/packet).
 * Wire format: [payload | nonce_le64 (8B) | HMAC-SHA3-256 (32B)]
 *
 * Typical flow:
 *   1. Drone generates KEM keypair, exports EK to GCS.
 *   2. GCS calls cleitonq_kem_encapsulate() → gets (ciphertext, session_key).
 *      GCS sends ciphertext to drone.
 *   3. Drone calls cleitonq_kem_decapsulate() → gets session_key.
 *   4. Both sides call cleitonq_channel_new(session_key, CLEITONQ_DOMAIN_C2).
 *   5. GCS signs packets with cleitonq_channel_sign().
 *   6. Drone verifies with cleitonq_channel_verify().
 */

/**
 * Creates an authenticated channel from a 32-byte session key.
 *
 * @param session_key  Pointer to exactly 32 bytes (from KEM shared secret).
 * @param domain       CLEITONQ_DOMAIN_C2, TELEMETRY, or MESH.
 * @return             Opaque channel handle, or NULL on invalid input.
 *                     Must be freed with cleitonq_channel_free().
 */
cleitonq_channel_t *cleitonq_channel_new(const uint8_t session_key[32], int domain);

/** Frees a channel. Safe to call with NULL. */
void cleitonq_channel_free(cleitonq_channel_t *ch);

/**
 * Signs a payload and writes the authenticated packet to `out`.
 *
 * `out` must have capacity >= payload_len + CLEITONQ_CHANNEL_OVERHEAD.
 * The nonce must be strictly increasing across calls on this channel.
 *
 * @return Total packet length on success, or negative error code.
 */
int cleitonq_channel_sign(
    const cleitonq_channel_t *ch,
    const uint8_t            *payload,
    size_t                    payload_len,
    uint64_t                  nonce,
    uint8_t                  *out,
    size_t                    out_cap
);

/**
 * Verifies a packet and extracts the payload.
 *
 * @param last_nonce   Highest nonce accepted so far. Packets with nonce <=
 *                     last_nonce are rejected (replay protection).
 * @param payload_out  Output buffer for the payload (may be NULL to skip copy).
 *                     Must be >= packet_len bytes.
 * @param nonce_out    Receives the accepted nonce (may be NULL).
 *
 * @return Payload length (>= 0) on success, or negative error code.
 *         CLEITONQ_ERR_VERIFY means authentication failed or replay detected.
 */
int cleitonq_channel_verify(
    const cleitonq_channel_t *ch,
    const uint8_t            *packet,
    size_t                    packet_len,
    uint64_t                  last_nonce,
    uint8_t                  *payload_out,
    size_t                    payload_cap,
    uint64_t                 *nonce_out
);

/* ── ML-DSA-87 command signing ────────────────────────────────────────────── */
/*
 * Non-repudiable command signing with ML-DSA-87 (FIPS 204).
 * Use for: ARM, DISARM, WAYPOINT, MODE_CHANGE, MISSION_START.
 * Overhead: 4635 bytes per signed command (relay-transparent on CleitonQ fleets).
 *
 * Wire format: [payload | nonce_le64 (8B) | ML-DSA-87 signature (4627B)]
 */

/** Generates a fresh ML-DSA-87 signing key. Free with cleitonq_dsa_sk_free(). */
cleitonq_signing_key_t *cleitonq_dsa_keygen(void);

/**
 * Reconstructs a signing key from its 32-byte seed.
 * Free with cleitonq_dsa_sk_free().
 */
cleitonq_signing_key_t *cleitonq_dsa_sk_from_seed(const uint8_t seed[32]);

/**
 * Exports the 32-byte signing key seed to `seed_out`.
 * Store with mode 0600. The seed reconstructs the full signing key.
 */
int cleitonq_dsa_sk_to_seed(const cleitonq_signing_key_t *sk, uint8_t seed_out[32]);

/**
 * Derives the verifying key from a signing key.
 * Free with cleitonq_dsa_vk_free(). Safe to distribute to drones.
 */
cleitonq_verifying_key_t *cleitonq_dsa_verifying_key(const cleitonq_signing_key_t *sk);

/**
 * Reconstructs a verifying key from its 2592-byte encoding.
 * Free with cleitonq_dsa_vk_free().
 */
cleitonq_verifying_key_t *cleitonq_dsa_vk_from_bytes(const uint8_t vk_bytes[2592]);

/**
 * Exports the 2592-byte verifying key to `vk_out`.
 * This is the public key — distribute freely to all drones.
 */
int cleitonq_dsa_vk_to_bytes(const cleitonq_verifying_key_t *vk, uint8_t vk_out[2592]);

/** Frees a signing key. Safe to call with NULL. */
void cleitonq_dsa_sk_free(cleitonq_signing_key_t *sk);

/** Frees a verifying key. Safe to call with NULL. */
void cleitonq_dsa_vk_free(cleitonq_verifying_key_t *vk);

/**
 * Signs a payload with ML-DSA-87 and writes the packet to `out`.
 *
 * `out` must have capacity >= payload_len + CLEITONQ_DSA_OVERHEAD.
 * @return Total packet length on success, or negative error code.
 */
int cleitonq_dsa_sign(
    const cleitonq_signing_key_t *sk,
    const uint8_t                *payload,
    size_t                        payload_len,
    uint64_t                      nonce,
    uint8_t                      *out,
    size_t                        out_cap
);

/**
 * Verifies an ML-DSA-87 signed packet and extracts the payload.
 * Timing-safe: returns CLEITONQ_ERR_VERIFY without revealing why.
 *
 * @return Payload length (>= 0) on success, or negative error code.
 */
int cleitonq_dsa_verify(
    const cleitonq_verifying_key_t *vk,
    const uint8_t                  *packet,
    size_t                          packet_len,
    uint64_t                        last_nonce,
    uint8_t                        *payload_out,
    size_t                          payload_cap,
    uint64_t                       *nonce_out
);

/* ── ML-KEM-1024 session key establishment ────────────────────────────────── */
/*
 * Post-quantum key exchange (FIPS 203). Establishes a 32-byte shared secret
 * over an insecure channel. Feed the shared secret into cleitonq_channel_new().
 *
 * Protocol:
 *   DRONE                                GCS
 *   cleitonq_kem_keygen()
 *   cleitonq_kem_ek_bytes() → EK ────────►
 *   cleitonq_kem_dk_seed()  → store
 *                              cleitonq_kem_encapsulate(EK) → (CT, SS)
 *                      CT ◄────
 *   cleitonq_kem_decapsulate(DK_SEED, CT) → SS
 *   Both: cleitonq_channel_new(SS, DOMAIN_C2)
 */

/** Generates a fresh ML-KEM-1024 key pair. Free with cleitonq_kem_keypair_free(). */
cleitonq_kem_keypair_t *cleitonq_kem_keygen(void);

/** Frees a KEM key pair. Safe to call with NULL. */
void cleitonq_kem_keypair_free(cleitonq_kem_keypair_t *kp);

/**
 * Exports the 1568-byte public encapsulation key (EK) to `ek_out`.
 * Share this with the ground station. It is NOT secret.
 * `out_cap` must be >= CLEITONQ_KEM_EK_BYTES.
 */
int cleitonq_kem_ek_bytes(
    const cleitonq_kem_keypair_t *kp,
    uint8_t                      *ek_out,
    size_t                        out_cap
);

/**
 * Exports the 64-byte decapsulation key seed (DK) to `dk_out`.
 * Keep this PRIVATE on the drone. Store with mode 0600.
 * `out_cap` must be >= CLEITONQ_KEM_DK_SEED_BYTES.
 */
int cleitonq_kem_dk_seed(
    const cleitonq_kem_keypair_t *kp,
    uint8_t                      *dk_out,
    size_t                        out_cap
);

/**
 * Ground station: encapsulates a fresh session key using the drone's EK.
 *
 * @param ek_bytes  1568-byte encapsulation key received from drone.
 * @param ct_out    1568-byte output buffer for ciphertext (send to drone).
 * @param ss_out    32-byte output buffer for session key (keep locally).
 *
 * @return CLEITONQ_OK on success, or negative error code.
 */
int cleitonq_kem_encapsulate(
    const uint8_t ek_bytes[CLEITONQ_KEM_EK_BYTES],
    uint8_t       ct_out[CLEITONQ_KEM_CT_BYTES],
    uint8_t       ss_out[CLEITONQ_KEM_SS_BYTES]
);

/**
 * Drone: recovers the session key from the ground station's ciphertext.
 *
 * @param dk_seed   64-byte DK seed stored on drone.
 * @param ciphertext 1568-byte ciphertext received from GCS.
 * @param ss_out    32-byte output buffer for the session key.
 *
 * @return CLEITONQ_OK on success, or negative error code.
 */
int cleitonq_kem_decapsulate(
    const uint8_t dk_seed[CLEITONQ_KEM_DK_SEED_BYTES],
    const uint8_t ciphertext[CLEITONQ_KEM_CT_BYTES],
    uint8_t       ss_out[CLEITONQ_KEM_SS_BYTES]
);

#ifdef __cplusplus
}
#endif

#endif /* CLEITONQ_H */

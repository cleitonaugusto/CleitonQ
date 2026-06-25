// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. MIT OR Apache-2.0.
//
// Thin C++ wrappers around the CleitonQ C API for use in ROS2 nodes.
// Link with: target_link_libraries(my_node PRIVATE CleitonQ::capi)

#pragma once

#include <cleitonq.h>
#include <cstdint>
#include <vector>
#include <optional>
#include <stdexcept>
#include <memory>

namespace cleitonq_ros2 {

// ── RAII wrappers ─────────────────────────────────────────────────────────────

struct ChannelDeleter {
    void operator()(cleitonq_channel_t *p) const { cleitonq_channel_free(p); }
};
using ChannelPtr = std::unique_ptr<cleitonq_channel_t, ChannelDeleter>;

struct DsaSkDeleter {
    void operator()(cleitonq_signing_key_t *p) const { cleitonq_dsa_sk_free(p); }
};
using DsaSkPtr = std::unique_ptr<cleitonq_signing_key_t, DsaSkDeleter>;

struct DsaVkDeleter {
    void operator()(cleitonq_verifying_key_t *p) const { cleitonq_dsa_vk_free(p); }
};
using DsaVkPtr = std::unique_ptr<cleitonq_verifying_key_t, DsaVkDeleter>;

struct KemKpDeleter {
    void operator()(cleitonq_kem_keypair_t *p) const { cleitonq_kem_keypair_free(p); }
};
using KemKpPtr = std::unique_ptr<cleitonq_kem_keypair_t, KemKpDeleter>;

// ── AuthChannel helper ────────────────────────────────────────────────────────

class AuthChannel {
public:
    explicit AuthChannel(const uint8_t session_key[32], int domain = CLEITONQ_DOMAIN_C2) {
        ch_.reset(cleitonq_channel_new(session_key, domain));
        if (!ch_) throw std::runtime_error("cleitonq_channel_new failed");
    }

    // Signs payload with nonce. Returns wire packet (payload + 40B overhead).
    std::vector<uint8_t> sign(const std::vector<uint8_t> &payload, uint64_t nonce) const {
        std::vector<uint8_t> out(payload.size() + CLEITONQ_CHANNEL_OVERHEAD);
        int n = cleitonq_channel_sign(
            ch_.get(), payload.data(), payload.size(), nonce,
            out.data(), out.size());
        if (n < 0) throw std::runtime_error("cleitonq_channel_sign failed: " + std::to_string(n));
        out.resize(static_cast<size_t>(n));
        return out;
    }

    // Verifies packet. Returns {payload, nonce} or nullopt on failure.
    struct Verified { std::vector<uint8_t> payload; uint64_t nonce; };
    std::optional<Verified> verify(const std::vector<uint8_t> &packet, uint64_t last_nonce) const {
        std::vector<uint8_t> payload(packet.size());
        uint64_t nonce = 0;
        int n = cleitonq_channel_verify(
            ch_.get(), packet.data(), packet.size(), last_nonce,
            payload.data(), payload.size(), &nonce);
        if (n < 0) return std::nullopt;
        payload.resize(static_cast<size_t>(n));
        return Verified{std::move(payload), nonce};
    }

private:
    ChannelPtr ch_;
};

// ── KEM session establishment helper ─────────────────────────────────────────

struct KemResult {
    std::vector<uint8_t> ciphertext;          // 1568 bytes — send to drone
    std::array<uint8_t, 32> session_key;      // keep locally
};

// Ground station: generate session key from drone's encapsulation key.
inline KemResult kem_encapsulate(const std::vector<uint8_t> &ek_bytes) {
    if (ek_bytes.size() != CLEITONQ_KEM_EK_BYTES)
        throw std::invalid_argument("EK must be 1568 bytes");
    KemResult result;
    result.ciphertext.resize(CLEITONQ_KEM_CT_BYTES);
    int rc = cleitonq_kem_encapsulate(
        ek_bytes.data(),
        result.ciphertext.data(),
        result.session_key.data());
    if (rc != CLEITONQ_OK)
        throw std::runtime_error("cleitonq_kem_encapsulate failed: " + std::to_string(rc));
    return result;
}

// Drone: recover session key from ciphertext.
inline std::array<uint8_t, 32> kem_decapsulate(
    const std::array<uint8_t, 64> &dk_seed,
    const std::vector<uint8_t> &ciphertext)
{
    if (ciphertext.size() != CLEITONQ_KEM_CT_BYTES)
        throw std::invalid_argument("ciphertext must be 1568 bytes");
    std::array<uint8_t, 32> session_key{};
    int rc = cleitonq_kem_decapsulate(
        dk_seed.data(), ciphertext.data(), session_key.data());
    if (rc != CLEITONQ_OK)
        throw std::runtime_error("cleitonq_kem_decapsulate failed: " + std::to_string(rc));
    return session_key;
}

} // namespace cleitonq_ros2

import cleitonq

def test_dsa_roundtrip():
    sk_seed, vk = cleitonq.dsa_keygen()
    assert len(sk_seed) == cleitonq.DSA_SK_SEED_BYTES
    assert len(vk) == cleitonq.DSA_VK_BYTES

    payload = b"arm drone-alpha nonce=1"
    packet = cleitonq.dsa_sign(sk_seed, payload, nonce=1)
    recovered = cleitonq.dsa_verify(vk, packet, last_nonce=0)
    assert recovered == payload

def test_dsa_replay_rejected():
    sk_seed, vk = cleitonq.dsa_keygen()
    packet = cleitonq.dsa_sign(sk_seed, b"cmd", nonce=5)
    cleitonq.dsa_verify(vk, packet, last_nonce=4)
    try:
        cleitonq.dsa_verify(vk, packet, last_nonce=5)
        assert False, "replay must raise"
    except ValueError:
        pass

def test_dsa_tamper_rejected():
    sk_seed, vk = cleitonq.dsa_keygen()
    packet = bytearray(cleitonq.dsa_sign(sk_seed, b"cmd", nonce=1))
    packet[0] ^= 0xFF
    try:
        cleitonq.dsa_verify(vk, bytes(packet), last_nonce=0)
        assert False, "tampered must raise"
    except ValueError:
        pass

def test_kem_session():
    dk_seed, ek = cleitonq.kem_keygen()
    assert len(ek) == cleitonq.KEM_EK_BYTES
    assert len(dk_seed) == cleitonq.KEM_DK_SEED_BYTES

    ct, ss_gcs = cleitonq.kem_encapsulate(ek)
    assert len(ct) == cleitonq.KEM_CT_BYTES
    assert len(ss_gcs) == cleitonq.KEM_SS_BYTES

    ss_drone = cleitonq.kem_decapsulate(dk_seed, ct)
    assert ss_gcs == ss_drone

def test_channel_roundtrip():
    session_key = bytes(range(32))
    payload = b"altitude=50.0 heading=270.0"

    packet = cleitonq.channel_sign(session_key, cleitonq.DOMAIN_TELEMETRY, payload, nonce=1)
    recovered = cleitonq.channel_verify(session_key, cleitonq.DOMAIN_TELEMETRY, packet, last_nonce=0)
    assert recovered == payload

def test_channel_domain_separation():
    key = bytes([0x42] * 32)
    packet = cleitonq.channel_sign(key, cleitonq.DOMAIN_C2, b"cmd", nonce=1)
    try:
        cleitonq.channel_verify(key, cleitonq.DOMAIN_TELEMETRY, packet, last_nonce=0)
        assert False, "cross-domain must raise"
    except ValueError:
        pass

def test_full_session():
    # Complete flow: KEM session + HMAC channel + DSA signed command
    dk_seed, ek = cleitonq.kem_keygen()
    ct, session_key = cleitonq.kem_encapsulate(ek)
    session_key_drone = cleitonq.kem_decapsulate(dk_seed, ct)
    assert session_key == session_key_drone

    payload = b"waypoint lat=10.0 lon=20.0 alt=100.0"
    packet = cleitonq.channel_sign(session_key, cleitonq.DOMAIN_C2, payload, nonce=1)
    recovered = cleitonq.channel_verify(session_key_drone, cleitonq.DOMAIN_C2, packet, last_nonce=0)
    assert recovered == payload

if __name__ == "__main__":
    test_dsa_roundtrip()
    test_dsa_replay_rejected()
    test_dsa_tamper_rejected()
    test_kem_session()
    test_channel_roundtrip()
    test_channel_domain_separation()
    test_full_session()
    print("All tests passed.")

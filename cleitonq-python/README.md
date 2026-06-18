# cleitonq

Post-quantum authenticated C2 for embedded and autonomous systems.

Python bindings for the CleitonQ library — ML-KEM-1024 (FIPS 203), ML-DSA-87 (FIPS 204), HMAC-SHA3-256.

```python
import cleitonq

# Key generation
sk_seed, vk = cleitonq.dsa_keygen()

# Sign a command
packet = cleitonq.dsa_sign(sk_seed, b"arm drone-alpha", nonce=1)

# Verify
payload = cleitonq.dsa_verify(vk, packet, last_nonce=0)
```

Source: https://github.com/cleitonaugusto/CleitonQ

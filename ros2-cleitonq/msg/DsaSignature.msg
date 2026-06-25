# DsaSignature — ML-DSA-87 signed command for non-repudiable C2.
#
# Used for critical commands (ARM, DISARM, MISSION_START, MODE_CHANGE).
# Published on a sidecar topic (e.g. /arm_disarm/dsa) parallel to
# the command topic. Overhead: 4635 bytes per signed command.
#
# The ML-DSA-87 verifying key is distributed to all nodes during the
# key ceremony and is NOT transmitted per-command.
#
# Reference: https://github.com/cleitonaugusto/CleitonQ (dual-channel architecture)

uint64 sequence_id        # correlates with the command topic message
uint64 nonce              # monotonically increasing, anti-replay
uint8[] payload           # serialized command bytes (redundant copy for verification)
uint8[4627] signature     # ML-DSA-87 signature over (payload || nonce_le64)

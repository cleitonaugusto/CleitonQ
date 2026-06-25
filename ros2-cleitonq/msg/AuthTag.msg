# AuthTag — HMAC-SHA3-256 authentication tag for a ROS2 command.
#
# Published on a sidecar topic (e.g. /arm_disarm/auth) parallel to the
# command topic (/arm_disarm). The receiver correlates both by sequence_id
# and verifies the HMAC before acting on the command.
#
# This parallel-topic pattern prevents relay-transparent authentication
# stripping: a DDS bridge that re-serializes the command topic cannot
# silently discard this topic without also missing the correlation.
#
# Reference: https://datatracker.ietf.org/doc/draft-bezerra-relay-auth-transparency/
# Advisory:  GHSA-f5rj-mrxh-r7vm

uint64 sequence_id   # correlates with the authenticated command
uint64 nonce         # monotonically increasing, anti-replay
uint8[32] hmac_tag   # HMAC-SHA3-256 over (command_bytes || nonce_le64)

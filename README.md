# Wolfpack-Double-Ratchet

An example implementation of the Double-Ratchet algorithm. This is not hardened for production use -- this is for educational purposes only. The Quilibrium codebase will include a hardened version (among other cryptography). 

## Differences from Signal's Double-Ratchet

- X3DH consumes a _signed_ identity key, instead of a raw identity key, to maintain key hygiene of the identity key used for signing, and the distinct key used for identity in the X3DH agreement
- All keys are P-256 to be easy to use with hardware and browser cryptography
support
- The hashing algorithm used is SHA-3

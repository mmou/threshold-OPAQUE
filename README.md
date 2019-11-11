# OPAQUE for (threshold) password-protected secret sharing

WIP

TODO: write README.

Implementation of OPAQUE and threshold OPAQUE, which can be used to implement
a threshold password-protected secret sharing (ppss) scheme
(https://eprint.iacr.org/2017/363.pdf).

We use a Noise XX handshake for the key exchange protocol.
We use Pedersen DKG for distributed key generation for the threshold OPRF.

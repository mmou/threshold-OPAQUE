# OPAQUE asymmetric PAKE, and its threshold implementation

## OPAQUE

Implementation of OPAQUE protocol
(https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-03,
https://eprint.iacr.org/2018/163.pdf), an asymmetric PAKE that support PKI-free
mutual client-server authentication; and of threshold OPAQUE
(https://eprint.iacr.org/2017/363.pdf), in which multiple servers are used to
increase server security.

OPAQUE is pre-computation attack resistant because the server never receives or
stores the user's password (cleartext or hashed), and it also never transmits
the per-user salt in the clear. It accomplishes this by using a neat primitive
called an OPRF (oblivious pseudorandom function,
https://tools.ietf.org/html/draft-sullivan-cfrg-voprf-03). An OPRF is an
interactive protocol that allows the client to compute the output of
a function, where the server holds the PRF secret key, and the server doesn't
learn of the client's input or output. In this case, the OPRF input is the
client's password, the OPRF key is the per-user salt (which stays on the
server), and the output is a "randomized" password (rwd) that leaks no
information about the client's password. The client uses the rwd to encrypt an
"envelope" containing the keypair it will use for login key exchange; the
encrypted envelope is stored on the server upon successful registration.

To better understand OPRFs, it was helpful for me to read a paper (also by
Jarecki and Krawczyk) that also uses an OPRF to implement a password manager:
https://blog.devolutions.net/2018/09/what-are-sphinx-and-de-pake,
https://eprint.iacr.org/2018/695.

Look at the test in the `opaque` module for more detail about the register and
login flows. In tests, we use a Noise XX handshake
(https://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental)
for the key exchange protocol.


## Threshold OPAQUE

The paper on TOPPSS (threshold password-protected secret sharing
https://eprint.iacr.org/2017/363.pdf) describes a generic transformation of an
OPRF into a threshold OPRF (also see:
https://csrc.nist.gov/CSRC/media/Presentations/Threshold-Cryptography-Ready-for-Prime-Time/images-media/krawczyk-hugo-keynote-NTCW19.pdf).
A threshold OPRF requires `n` servers (the OPRF signers) to run a DKG protocol
to generate private key shares, which are used as each OPRF signer's secret
key. The OPRF signers each sign the client's blinded input with their secret
key (as usual). Then, the client's output is reconstructed by combining at
least `t` (minimum number required to reconstruct secret)'s signed inputs.

We use the threshold OPRF to support threshold OPAQUE. No client-side
modifications are necessary. For ease of use, this implementation designates
one server to directly interact with the client, and to reconstruct the OPRF
output that is sent back to the client. 

We implemented Pedersen DKG
(https://pdfs.semanticscholar.org/642b/d1bbc86c7750cef9fa770e9e4ba86bd49eb9.pdf)
for the distributed key generation protocol used by the threshold OPRF. The
Pedersen DKG protocol is essentially `n` parallel runs of Feldman VSS
(verifiable secret sharing), where each player is a dealer. We use move
semantics, as inspired by session types
(https://blog.chain.com/bulletproof-multi-party-computation-in-rust-with-session-types-b3da6e928d5d),
to enforce protocol flow at compile-time.

Look at the tests in the `dkg` module for more detals about the Feldman VSS and
Pedersen DKG protocols. 

Look at the test in the `topaque` module for more detail about the threshold
OPAQUE register and login flows.

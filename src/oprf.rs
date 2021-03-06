use crate::errors::*;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use digest::Digest;
use generic_array::GenericArray;
use rand_core::{CryptoRng, RngCore};
use sha2::{Sha256, Sha512};
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::KEYBYTES;

pub const PWD_LEN: usize = 64; // required by RistrettoPoint::from_uniform_bytes
pub const RWD_LEN: usize = KEYBYTES; // 32

#[derive(Debug, Copy, Clone)]
pub struct OprfKey {
    key: Scalar,
}

impl OprfKey {
    pub fn new(key: Scalar) -> Self {
        OprfKey { key }
    }

    pub fn random<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        OprfKey {
            key: Scalar::random(rng),
        }
    }

    pub fn pub_key(&self) -> CompressedRistretto {
        (self.key * RISTRETTO_BASEPOINT_POINT).compress()
    }

    pub fn sign(&self, input: RistrettoPoint) -> RistrettoPoint {
        input * self.key
    }
}

pub struct OprfVerifier {
    input: [u8; PWD_LEN],
    blind: Scalar,
}

impl OprfVerifier {
    pub fn new<R>(pwd: &str, rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        // doing this instead of RistrettoPoint::hash_from_bytes in order to store a fixed-size array in OprfVerifier
        let mut hasher = Sha512::default();
        hasher.input(pwd.as_bytes());
        let hex: GenericArray<u8, <Sha512 as digest::Digest>::OutputSize> = hasher.result();
        let mut input = [0u8; PWD_LEN];
        input.copy_from_slice(&hex.to_vec()[..PWD_LEN]);

        OprfVerifier {
            input,
            blind: Scalar::random(rng),
        }
    }

    pub fn blind(&mut self) -> Result<CompressedRistretto, TokenError> {
        let point = RistrettoPoint::from_uniform_bytes(&self.input);
        let blinded = point * self.blind;
        Ok(blinded.compress())
    }

    pub fn unblind(
        &mut self,
        server_pub_key: CompressedRistretto,
        signed_output: CompressedRistretto,
    ) -> Result<[u8; RWD_LEN], TokenError> {
        let unblinded_output = signed_output
            .decompress()
            .ok_or(TokenError(InternalError::DecompressionError))?
            * self.blind.invert();
        let mut hasher = Sha256::default();
        hasher.input(&self.input[..]);
        hasher.input(server_pub_key.as_bytes());
        hasher.input(unblinded_output.compress().as_bytes());
        let hex: GenericArray<u8, <Sha256 as digest::Digest>::OutputSize> = hasher.result();
        let mut rwd = [9u8; RWD_LEN];
        rwd.copy_from_slice(&hex.to_vec()[..RWD_LEN]);
        Ok(rwd)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct OprfProver {
    key: OprfKey,
}

impl OprfProver {
    pub fn new(key: OprfKey) -> Self {
        OprfProver { key }
    }

    // returns the (key's pub key, and the signed blinded output)
    pub fn sign(
        &mut self,
        input: CompressedRistretto,
    ) -> Result<(CompressedRistretto, CompressedRistretto), TokenError> {
        let output = self.key.sign(
            input
                .decompress()
                .ok_or(TokenError(InternalError::DecompressionError))?,
        );
        Ok((self.key.pub_key(), output.compress()))
    }

    // consumes; don't allow key to be reused
    pub fn return_key(self) -> OprfKey {
        self.key
    }
}

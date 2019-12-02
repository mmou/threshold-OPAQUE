use crate::dkg::*;
use crate::errors::*;
use crate::oprf::*;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

use std::vec::Vec;

/// Threshold OPRF players use Pedersen DKG for generation of the secret scalar.
///
/// ThresholdOprfProverPlayer uses move semantics to enforce protocol flow at compile-time.
/// 1) A ThresholdOprfProverInitPlayer calls commit() to become a PedersenVSSCommittedDealer.
/// 2) A ThresholdOprfProverCommittedPlayer has committed broadcast_vals and secret_shares.
/// 3) The broadcast_vals are publicly announced, and each secret in secret_shares is sent to its
/// respective ThresholdOprfProverCommittedPlayer.
/// 4) A player that that has received its secret shares is a ThresholdOprfProverReadyPlayer.
/// 5) A ReadyPlayer is able to verify other players and be part of reconstructing the secret.
///
/// To summarize:
/// ThresholdOprfProverPlayer ->
///     ThresholdOprfProverInitPlayer w/ PedersenDKGInitPlayer ->
///     ThresholdOprfProverCommittedPlayer w/ PedersenDKGCommittedPlayer ->
///     ThresholdOprfProverReadyPlayer w/ PedersenDKGReadyPlayer
pub struct ThresholdOprfProverPlayer {}

pub struct ThresholdOprfProverInitPlayer {
    dkg: PedersenDKGInitPlayer,
}

pub struct ThresholdOprfProverCommittedPlayer {
    pub dkg: PedersenDKGCommittedPlayer,
}

pub struct ThresholdOprfProverReadyPlayer {
    pub dkg: PedersenDKGReadyPlayer,
    pub oprf: OprfProver,
}

impl ThresholdOprfProverPlayer {
    pub fn new(dkg: PedersenDKGInitPlayer) -> ThresholdOprfProverInitPlayer {
        ThresholdOprfProverInitPlayer { dkg }
    }
}

impl ThresholdOprfProverInitPlayer {
    pub fn commit(self) -> ThresholdOprfProverCommittedPlayer {
        ThresholdOprfProverCommittedPlayer {
            dkg: self.dkg.commit(),
        }
    }
}

impl ThresholdOprfProverCommittedPlayer {
    pub fn receive(self, received_shares: Vec<Scalar>) -> ThresholdOprfProverReadyPlayer {
        let dkg = self.dkg.receive(received_shares);
        let oprf: OprfProver = OprfProver::new(OprfKey::new(dkg.get_shares_sum()));

        ThresholdOprfProverReadyPlayer { dkg, oprf }
    }
}

impl ThresholdOprfProverReadyPlayer {
    /// returns (OPRF secret's pub_key, signed OPRF output)
    pub fn reconstruct(
        &self,
        compressed_pub_keys_and_responses: Vec<(u64, (CompressedRistretto, CompressedRistretto))>,
    ) -> Result<(CompressedRistretto, CompressedRistretto), TokenError> {
        assert!(compressed_pub_keys_and_responses.len() >= self.dkg.get_t()); // TODO: replace with err
        let (server_ids, points): (Vec<u64>, Vec<(CompressedRistretto, CompressedRistretto)>) =
            compressed_pub_keys_and_responses.iter().cloned().unzip();
        let pub_keys: Vec<RistrettoPoint> =
            points.iter().filter_map(|(k, _)| k.decompress()).collect();
        let responses: Vec<RistrettoPoint> =
            points.iter().filter_map(|(_, r)| r.decompress()).collect();

        if pub_keys.len() != server_ids.len() || responses.len() != server_ids.len() {
            return Err(TokenError(InternalError::DecompressionError));
        }

        let pub_key = reconstruct_point(server_ids.iter().cloned().zip(pub_keys).collect());
        let response = reconstruct_point(server_ids.iter().cloned().zip(responses).collect());
        Ok((pub_key.compress(), response.compress()))
    }
}

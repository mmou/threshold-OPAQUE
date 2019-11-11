use crate::tppss::DKGRecord;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};

/// Feldman VSS involves one dealer and n non-dealer players.
///
/// FeldmanVSSDealer and FeldmanVSSPlayer use move semantics to enforce protocol flow at compile-time.
/// 1) A FeldmanVSSInitDealer calls commit() to become a FeldmanVSSCommittedDealer.
/// 2) A FeldmanVSSCommittedDealer has committed broadcast_vals and secret_shares.
/// 3) The broadcast_vals are publicly announced, and each secret in secret_shares is sent to its
/// respective FeldmanVSSInitPlayer.
/// 4) A FeldmanVSSInitPlayer that that has received its secret share is a FeldmanVSSReadyPlayer.
/// 5) A FeldmanVSSReadyPlayer is able to verify the dealer and be part of reconstructing the secret.
///
/// This library does not implement code to complain about or keep track of an unverified dealer.
///
/// So to summarize:
/// 1) FeldmanVSSDealer -> FeldmanVSSInitDealer -> FeldmanVSSCommittedDealer
/// 2) FeldmanVSSPlayer -> FeldmanVSSInitPlayer -> FeldmanVSSReadyPlayer
/// FeldmanVSSReadyPlayer may complain about the FeldmanVSSCommittedDealer;
/// FeldmanVSSCommittedDealer may be disqualified, but that's up to the players to keep track of.
///
pub struct FeldmanVSSDealer {}

pub struct FeldmanVSSInitDealer {
    t: usize,            // num shares required to reconstruct secret
    n: usize,            // num players, n >= t
    secret: Scalar,      // a_0
    coeffs: Vec<Scalar>, // len = t, coeffs[0] = secret
}

#[derive(Debug, Clone)]
pub struct FeldmanVSSCommittedDealer {
    t: usize,
    n: usize,
    secret: Scalar,                     // a_0
    coeffs: Vec<Scalar>,                // len = t, coeffs[0] = secret
    broadcast_val: Vec<RistrettoPoint>, // len = t; ith value is the commitment for the ith coeff (0-indexed)
    secret_shares: Vec<Scalar>, // len = n; ith value is sent to player id i+1 (because ids are 1-indexed while lists are 0-indexed)
}

impl FeldmanVSSDealer {
    fn new<R>(secret: Scalar, t: usize, n: usize, rng: &mut R) -> FeldmanVSSInitDealer
    where
        R: RngCore + CryptoRng,
    {
        assert!(t <= n); // TODO: replace with err
        let mut coeffs = vec![Default::default(); t];
        coeffs[0] = secret;
        // generate random coeffs
        for c in coeffs[1..].iter_mut() {
            *c = Scalar::random(rng);
        }

        FeldmanVSSInitDealer {
            t,
            n,
            secret,
            coeffs,
        }
    }

    pub fn new_with_random_secret<R>(t: usize, n: usize, rng: &mut R) -> FeldmanVSSInitDealer
    where
        R: RngCore + CryptoRng,
    {
        FeldmanVSSDealer::new(Scalar::random(rng), t, n, rng)
    }
}

impl FeldmanVSSInitDealer {
    pub fn commit(self) -> FeldmanVSSCommittedDealer {
        let mut committed = FeldmanVSSCommittedDealer {
            t: self.t,
            n: self.n,
            secret: self.secret,
            coeffs: self.coeffs,
            broadcast_val: vec![Default::default(); self.t],
            secret_shares: vec![Default::default(); self.n],
        };

        // broadcast_val, the public commitments
        committed.broadcast_val = committed
            .coeffs
            .iter()
            .map(|coeff| coeff * RISTRETTO_BASEPOINT_POINT)
            .collect();

        // secret_shares, sent to each other player
        for (share, user_id) in committed.secret_shares.iter_mut().zip(1u64..) {
            let user_scalar = Scalar::from(user_id);
            *share = committed
                .coeffs
                .iter()
                .scan(Scalar::one(), |power, coeff| {
                    let coeff_output = coeff * *power;
                    *power *= user_scalar;
                    Some(coeff_output)
                })
                .sum::<Scalar>();
        }

        committed
    }
}

impl FeldmanVSSCommittedDealer {
    pub fn get_share(&self, other_id: u64) -> Scalar {
        self.secret_shares[(other_id - 1) as usize]
    }

    pub fn from(
        t: usize,
        n: usize,
        secret: Scalar,
        coeffs: Vec<Scalar>,
        broadcast_val: Vec<RistrettoPoint>,
        secret_shares: Vec<Scalar>,
    ) -> Self {
        FeldmanVSSCommittedDealer {
            t,
            n,
            secret,
            coeffs,
            broadcast_val,
            secret_shares,
        }
    }
}

pub struct FeldmanVSSPlayer {}

pub struct FeldmanVSSInitPlayer {
    id: u64,
    t: usize,
    n: usize,
}

pub struct FeldmanVSSReadyPlayer {
    id: u64,
    t: usize,
    n: usize,
    received_share: Scalar,
}

impl FeldmanVSSPlayer {
    // player id, t-degree polynomial, n total players
    fn new(id: u64, t: usize, n: usize) -> FeldmanVSSInitPlayer {
        FeldmanVSSInitPlayer { id, t, n }
    }
}

impl FeldmanVSSInitPlayer {
    fn receive(self, secret: Scalar) -> FeldmanVSSReadyPlayer {
        FeldmanVSSReadyPlayer {
            id: self.id,
            t: self.t,
            n: self.n,
            received_share: secret,
        }
    }
}

// verifies the dealer using its received share and the public broadcast_vals
impl FeldmanVSSReadyPlayer {
    fn verify(&self, broadcast_vals: &[RistrettoPoint]) -> bool {
        verify(self.id, self.t, broadcast_vals, self.received_share)
    }
}

/// Pedersen DKG (https://pdfs.semanticscholar.org/642b/d1bbc86c7750cef9fa770e9e4ba86bd49eb9.pdf)
/// is essentially n parallel runs of Feldman VSS, where each player is a dealer.
///
/// PedersenDKGPlayer uses move semantics to enforce protocol flow at compile-time.
/// 1) A PedersenVSSInitDealer calls commit() to become a PedersenVSSCommittedDealer.
/// 2) A PedersenVSSCommittedDealer has committed broadcast_vals and secret_shares.
/// 3) The broadcast_vals are publicly announced, and each secret in secret_shares is sent to its
/// respective PedersenDKGCommittedPlayer.
/// 4) A player that that has received its secret shares is a PedersenDKGReadyPlayer.
/// 5) A ReadyPlayer is able to verify other players and be part of reconstructing the secret.
///
/// This library does not implement code to complain about or keep track of unverified players.
///
/// To summarize:
/// PedersenDKGPlayer ->
///     PedersenDKGInitPlayer w/ FeldmanVSSInitPlayer ->
///     PedersenDKGCommittedPlayer w/ FeldmanVSSCommittedPlayer ->
///     PedersenDKGReadyPlayer w/ FeldmanVSSCommittedPlayer
/// PedersenDKGReadyPlayer may complain about other players;
/// A player may be disqualified, but that's up to the players to keep track of.
pub struct PedersenDKGPlayer {}

pub struct PedersenDKGInitPlayer {
    id: u64,
    vss: FeldmanVSSInitDealer,
}

pub struct PedersenDKGCommittedPlayer {
    id: u64,
    pub vss: FeldmanVSSCommittedDealer,
}

#[derive(Debug, Clone)]
pub struct PedersenDKGReadyPlayer {
    id: u64,
    vss: FeldmanVSSCommittedDealer,
    received_shares: Vec<Scalar>, // len = n; ith value is received from player id i+1 (because ids are 1-indexed)
}

impl PedersenDKGPlayer {
    pub fn new(id: u64, vss: FeldmanVSSInitDealer) -> PedersenDKGInitPlayer {
        PedersenDKGInitPlayer { id, vss }
    }
}

impl PedersenDKGInitPlayer {
    pub fn commit(self) -> PedersenDKGCommittedPlayer {
        PedersenDKGCommittedPlayer {
            id: self.id,
            vss: self.vss.commit(),
        }
    }
}

impl PedersenDKGCommittedPlayer {
    pub fn receive(self, received_shares: Vec<Scalar>) -> PedersenDKGReadyPlayer {
        PedersenDKGReadyPlayer {
            id: self.id,
            vss: self.vss,
            received_shares,
        }
    }
}

impl PedersenDKGReadyPlayer {
    pub fn get_t(&self) -> usize {
        self.vss.t
    }

    pub fn get_share(&self, id: u64) -> Scalar {
        self.received_shares[id as usize - 1]
    }

    pub fn get_shares(&self) -> Vec<Scalar> {
        self.received_shares.clone()
    }

    pub fn get_shares_sum(&self) -> Scalar {
        self.received_shares.iter().sum()
    }

    // consumes secret
    pub fn return_secret(self) -> Scalar {
        self.vss.secret
    }

    // this player verifies player other_id=i using the secret share that player i sent to this player, and using player i's t public broadcast values (where t = power of polynomial)
    fn verify(&self, other_id: u64, received_broadcast_vals: &[RistrettoPoint]) -> bool {
        verify(
            self.id, // my id
            self.vss.t,
            received_broadcast_vals,
            self.get_share(other_id),
        )
    }

    pub fn from(id: u64, vss: FeldmanVSSCommittedDealer, received_shares: Vec<Scalar>) -> Self {
        PedersenDKGReadyPlayer {
            id,
            vss,
            received_shares,
        }
    }

    pub fn to_record(&self) -> DKGRecord {
        DKGRecord::new(
            self.id,
            self.vss.t,
            self.vss.n,
            self.vss.secret,
            self.vss.coeffs.clone(),
            self.vss.broadcast_val.clone(),
            self.vss.secret_shares.clone(),
            self.received_shares.clone(),
        )
    }
}

// verify share received from other server using their broadcast_vals
fn verify(
    my_id: u64,
    t: usize,
    received_broadcast_vals: &[RistrettoPoint],
    received_share: Scalar,
) -> bool {
    assert_eq!(received_broadcast_vals.len(), t);
    let user_scalar = Scalar::from(my_id);
    let output: RistrettoPoint = received_broadcast_vals
        .iter()
        .scan(Scalar::one(), |power, &broadcast| {
            let coeff_output = broadcast * *power;
            *power *= user_scalar;
            Some(coeff_output)
        })
        .sum::<RistrettoPoint>();

    output.compress() == (RISTRETTO_BASEPOINT_POINT * received_share).compress()
}

// use lagrange coefficients to reconstruct secret from t secret shares
// secret = f(0) = sum of c_i * f(i) for server id i in the set of t servers,
// where c_i is the lagrange coefficient = product of (j/j-i), for
// server id j in the set of t servers where i!=j
pub fn reconstruct_secret(shares: Vec<(u64, Scalar)>) -> Scalar {
    let t_ids: Vec<&u64> = shares.iter().map(|(id, _)| id).collect();

    // do this multiplication in the numerator once
    let js: Scalar = t_ids.iter().map(|&id| Scalar::from(*id)).product();

    shares.iter().fold(Scalar::zero(), |sum, (id, share)| {
        let coeff: Scalar = t_ids
            .iter()
            .map(|&j| {
                if *j != *id {
                    Scalar::from(*j) - Scalar::from(*id)
                } else {
                    Scalar::from(*id) // to cancel out in the numerator
                }
            })
            .product::<Scalar>()
            .invert();
        sum + share * js * coeff
    })
}

pub fn reconstruct_point(shares: Vec<(u64, RistrettoPoint)>) -> RistrettoPoint {
    let t_ids: Vec<&u64> = shares.iter().map(|(id, _)| id).collect();

    // do this multiplication in the numerator once
    let js: Scalar = t_ids.iter().map(|&id| Scalar::from(*id)).product();

    shares
        .iter()
        .fold(RistrettoPoint::default(), |sum, (id, share)| {
            let coeff: Scalar = t_ids
                .iter()
                .map(|&j| {
                    if *j != *id {
                        Scalar::from(*j) - Scalar::from(*id)
                    } else {
                        Scalar::from(*id) // to cancel out in the numerator
                    }
                })
                .product::<Scalar>()
                .invert();
            sum + share * js * coeff
        })
}

#[cfg(test)]
mod tests {

    use super::*;
    use rand::rngs::OsRng;
    use rand::seq::SliceRandom;

    #[test]
    fn feldman_vss() {
        let mut rng = OsRng::new().unwrap();
        let secret = Scalar::random(&mut rng);

        let t = 3;
        let n = 5;
        let dealer: FeldmanVSSInitDealer = FeldmanVSSDealer::new(secret, t, n, &mut rng);
        let player1: FeldmanVSSInitPlayer = FeldmanVSSPlayer::new(1, t, n);
        let player2: FeldmanVSSInitPlayer = FeldmanVSSPlayer::new(2, t, n);
        let player3: FeldmanVSSInitPlayer = FeldmanVSSPlayer::new(3, t, n);
        let player4: FeldmanVSSInitPlayer = FeldmanVSSPlayer::new(4, t, n);
        let player5: FeldmanVSSInitPlayer = FeldmanVSSPlayer::new(5, t, n);

        let dealerc = dealer.commit();

        let player1r = player1.receive(dealerc.get_share(1));
        let player2r = player2.receive(dealerc.get_share(2));
        let player3r = player3.receive(dealerc.get_share(3));
        let player4r = player4.receive(dealerc.get_share(4));
        let player5r = player5.receive(dealerc.get_share(5));

        // player 1,..,3 verifying player 1
        assert!(player1r.verify(&dealerc.broadcast_val));
        assert!(player2r.verify(&dealerc.broadcast_val));
        assert!(player3r.verify(&dealerc.broadcast_val));
        assert!(player4r.verify(&dealerc.broadcast_val));
        assert!(player5r.verify(&dealerc.broadcast_val));

        // in the case that share received by e.g. player3 is contested,
        // dealer (dealer) reveals the share it sent: `dealerc.get_share(3)`

        // secret can be reconstructed from any t servers' received shares
        let ids: Vec<FeldmanVSSReadyPlayer> =
            vec![player1r, player2r, player3r, player4r, player5r];
        for x in 0..4 {
            let sample: Vec<&FeldmanVSSReadyPlayer> = ids.choose_multiple(&mut rng, t).collect();
            assert_eq!(
                dealerc.secret,
                reconstruct_secret(vec![
                    (sample[0].id, sample[0].received_share),
                    (sample[1].id, sample[1].received_share),
                    (sample[2].id, sample[2].received_share),
                ])
            );
        }
    }

    #[test]
    fn pedersen_dkg() {
        let mut rng = OsRng::new().unwrap();
        let mut secrets: Vec<Scalar> = vec![Default::default(); 5];
        for s in secrets.iter_mut() {
            *s = Scalar::random(&mut rng);
        }

        let t = 3;
        let n = 5;
        let player1: PedersenDKGInitPlayer =
            PedersenDKGPlayer::new(1, FeldmanVSSDealer::new(secrets[0], t, n, &mut rng));
        let player2: PedersenDKGInitPlayer =
            PedersenDKGPlayer::new(2, FeldmanVSSDealer::new(secrets[1], t, n, &mut rng));
        let player3: PedersenDKGInitPlayer =
            PedersenDKGPlayer::new(3, FeldmanVSSDealer::new(secrets[2], t, n, &mut rng));
        let player4: PedersenDKGInitPlayer =
            PedersenDKGPlayer::new(4, FeldmanVSSDealer::new(secrets[3], t, n, &mut rng));
        let player5: PedersenDKGInitPlayer =
            PedersenDKGPlayer::new(5, FeldmanVSSDealer::new(secrets[4], t, n, &mut rng));

        let player1c = player1.commit();
        let player2c = player2.commit();
        let player3c = player3.commit();
        let player4c = player4.commit();
        let player5c = player5.commit();

        let shares1 = vec![
            player1c.vss.get_share(1),
            player2c.vss.get_share(1),
            player3c.vss.get_share(1),
            player4c.vss.get_share(1),
            player5c.vss.get_share(1),
        ];
        let shares2 = vec![
            player1c.vss.get_share(2),
            player2c.vss.get_share(2),
            player3c.vss.get_share(2),
            player4c.vss.get_share(2),
            player5c.vss.get_share(2),
        ];
        let shares3 = vec![
            player1c.vss.get_share(3),
            player2c.vss.get_share(3),
            player3c.vss.get_share(3),
            player4c.vss.get_share(3),
            player5c.vss.get_share(3),
        ];
        let shares4 = vec![
            player1c.vss.get_share(4),
            player2c.vss.get_share(4),
            player3c.vss.get_share(4),
            player4c.vss.get_share(4),
            player5c.vss.get_share(4),
        ];
        let shares5 = vec![
            player1c.vss.get_share(5),
            player2c.vss.get_share(5),
            player3c.vss.get_share(5),
            player4c.vss.get_share(5),
            player5c.vss.get_share(5),
        ];

        // player i sends secret_share[j-1] to user j, e.g. player 2 sends secret_share[2] to user 3
        let player1r = player1c.receive(shares1);
        let player2r = player2c.receive(shares2);
        let player3r = player3c.receive(shares3);
        let player4r = player4c.receive(shares4);
        let player5r = player5c.receive(shares5);

        // player 1,..,5 verifying player 2.
        assert!(player1r.verify(2, &player2r.vss.broadcast_val));
        assert!(player2r.verify(2, &player2r.vss.broadcast_val));
        assert!(player3r.verify(2, &player2r.vss.broadcast_val));
        assert!(player4r.verify(2, &player2r.vss.broadcast_val));
        assert!(player5r.verify(2, &player2r.vss.broadcast_val));

        // in the case that player 1's share received by e.g. player3 is contested,
        // dealer (dealer) reveals the share it sent: `player1c.vss.get_share(3);`

        // the generated DKG secret is the sum of the servers' VSS secrets,
        // which can be reconstructed with t servers' received shares.
        //
        // essentially, the polynomial f(x) we are reconstructing (where
        // f(0) is the generated secret) is equal to the sum of the n
        // polynomials that the n servers generated. therefore, this
        // polynomial can be reconstructed with t (x,f(x)) pairs, where
        // f(x) = sum of all of server x's received shares.
        let expected_secret = secrets.iter().sum::<Scalar>();
        let expected_point = expected_secret * RISTRETTO_BASEPOINT_POINT;

        let ids: Vec<PedersenDKGReadyPlayer> =
            vec![player1r, player2r, player3r, player4r, player5r];
        for x in 0..4 {
            let sample: Vec<&PedersenDKGReadyPlayer> = ids.choose_multiple(&mut rng, t).collect();

            // secret can be reconstructed from any t servers' received shares
            assert_eq!(
                expected_secret,
                reconstruct_secret(vec![
                    (sample[0].id, sample[0].get_shares_sum()),
                    (sample[1].id, sample[1].get_shares_sum()),
                    (sample[2].id, sample[2].get_shares_sum()),
                ])
            );

            // we can also reconstruct the public commitment to the expected secret
            assert_eq!(
                expected_point,
                reconstruct_point(vec![
                    (
                        sample[0].id,
                        sample[0].get_shares_sum() * RISTRETTO_BASEPOINT_POINT
                    ),
                    (
                        sample[1].id,
                        sample[1].get_shares_sum() * RISTRETTO_BASEPOINT_POINT
                    ),
                    (
                        sample[2].id,
                        sample[2].get_shares_sum() * RISTRETTO_BASEPOINT_POINT
                    ),
                ])
            );
        }
    }
}

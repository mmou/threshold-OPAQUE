#![no_std]
#![feature(try_trait)]
mod errors;

mod opaque;
mod oprf;

// Threshold OPAQUE implementation, which requires a DKG and threshold OPRF
mod topaque;

#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(feature = "std")]
mod dkg;

#[cfg(feature = "std")]
mod toprf;

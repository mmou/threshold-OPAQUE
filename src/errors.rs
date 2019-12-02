use core::fmt;
use core::fmt::Display;

#[cfg(feature = "std")]
use std::error::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
/// Internal crypto errors.  Most application-level developers will likely not
/// need to pay any attention to these.
pub enum InternalError {
    /// An error in the length of bytes handed to a constructor.
    /// Takes `name` of the type returning the error, and the `length` in bytes it expects
    BytesLengthError {
        name: &'static str,
        length: usize,
    },
    DecompressionError,
    VerifyError,
}

impl Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            InternalError::BytesLengthError { name: n, length: l } => {
                write!(f, "{} must be {} bytes in length", n, l)
            }
            InternalError::DecompressionError => {
                write!(f, "Failed to decompress a CompressedRistretto")
            }
            InternalError::VerifyError => write!(f, "Verification failed"),
        }
    }
}

#[cfg(feature = "std")]
impl Error for InternalError {}

/// Errors when converting keys and/or tokens to or from wire formats
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TokenError(pub(crate) InternalError);

impl Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "std")]
impl Error for TokenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        return Some(&self.0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ThresholdError {
    ArgumentError { n: usize, t: usize },
}

impl Display for ThresholdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ThresholdError::ArgumentError { n, t } => write!(f, "n ({}) is not >= t ({})", n, t),
        }
    }
}

#[cfg(feature = "std")]
impl Error for ThresholdError {}

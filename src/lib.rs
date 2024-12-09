mod sha3;
pub use sha3::{Sha3, sha3, eip191_hash_message, eip191_message};

pub mod constants;

use alloy_primitives::FixedBytes;
pub type B1368 = FixedBytes<1368>;

pub use base_primitives::{Signature, SignatureError};

use alloy_primitives::B256;
use core::mem::MaybeUninit;
use tiny_keccak::Hasher as _;
use core::fmt;

pub const EIP191_PREFIX: &str = "\x19Core Signed Message:\n";

/// Simple [`Sha3-256`] hasher.
///
/// Note that the "native-keccak" feature is not supported for this struct, and will default to the
/// [`tiny_keccak`] implementation.
#[derive(Clone)]
pub struct Sha3 {
    hasher: tiny_keccak::Sha3,
}

impl Default for Sha3 {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Sha3 {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sha3").finish_non_exhaustive()
    }
}

impl Sha3 {
    /// Creates a new [`Sha3`] hasher.
    #[inline]
    pub fn new() -> Self {
        Self { hasher: tiny_keccak::Sha3::v256() }
    }

    /// Absorbs additional input. Can be called multiple times.
    #[inline]
    pub fn update(&mut self, bytes: impl AsRef<[u8]>) {
        self.hasher.update(bytes.as_ref());
    }

    /// Pad and squeeze the state.
    #[inline]
    pub fn finalize(self) -> B256 {
        let mut output = MaybeUninit::<B256>::uninit();
        // SAFETY: The output is 32-bytes.
        unsafe { self.finalize_into_raw(output.as_mut_ptr().cast()) };
        // SAFETY: Initialized above.
        unsafe { output.assume_init() }
    }

    /// Pad and squeeze the state into `output`.
    ///
    /// # Panics
    ///
    /// Panics if `output` is not 32 bytes long.
    #[inline]
    #[track_caller]
    pub fn finalize_into(self, output: &mut [u8]) {
        self.finalize_into_array(output.try_into().unwrap())
    }

    /// Pad and squeeze the state into `output`.
    #[inline]
    pub fn finalize_into_array(self, output: &mut [u8; 32]) {
        self.hasher.finalize(output);
    }

    /// Pad and squeeze the state into `output`.
    ///
    /// # Safety
    ///
    /// `output` must point to a buffer that is at least 32-bytes long.
    #[inline]
    pub unsafe fn finalize_into_raw(self, output: *mut u8) {
        self.finalize_into_array(&mut *output.cast::<[u8; 32]>())
    }
}



/// Simple interface to the [`Sha3-256`] hash function.
///
/// [`Sha3`]: https://en.wikipedia.org/wiki/SHA-3
pub fn sha3<T: AsRef<[u8]>>(bytes: T) -> B256 {
    fn sha3(bytes: &[u8]) -> B256 {
        let mut output = MaybeUninit::<B256>::uninit();
        let mut hasher = Sha3::new();
        hasher.update(bytes);
        // SAFETY: Never reads from `output`.
        unsafe { hasher.finalize_into_raw(output.as_mut_ptr().cast()) };

        // SAFETY: Initialized above.
        unsafe { output.assume_init() }
    }

    sha3(bytes.as_ref())
}

/// Constructs a message according to [EIP-191] (version `0x01`).
///
/// The final message is a UTF-8 string, encoded as follows:
/// `"\x19Core Signed Message:\n" + message.length + message`
///
/// [EIP-191]: https://eips.ethereum.org/EIPS/eip-191
pub fn eip191_message<T: AsRef<[u8]>>(message: T) -> Vec<u8> {
    fn eip191_message(message: &[u8]) -> Vec<u8> {
        let len = message.len();
        let mut len_string_buffer = itoa::Buffer::new();
        let len_string = len_string_buffer.format(len);

        let mut eth_message = Vec::with_capacity(EIP191_PREFIX.len() + len_string.len() + len);
        eth_message.extend_from_slice(EIP191_PREFIX.as_bytes());
        eth_message.extend_from_slice(len_string.as_bytes());
        eth_message.extend_from_slice(message);
        eth_message
    }

    eip191_message(message.as_ref())
}

pub fn eip191_hash_message<T: AsRef<[u8]>>(message: T) -> B256 {
    sha3(eip191_message(message))
}



#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{b256, try_vec, utils::box_try_new};

    // test vector taken from:
    // https://web3js.readthedocs.io/en/v1.10.0/web3-eth-accounts.html#hashmessage
    #[test]
    fn test_hash_message() {
        let msg = "Hello World";
        let eip191_msg = eip191_message(msg);
        let hash = sha3(&eip191_msg);
        assert_eq!(
            eip191_msg,
            [EIP191_PREFIX.as_bytes(), msg.len().to_string().as_bytes(), msg.as_bytes()].concat()
        );
        assert_eq!(hash, b256!("aa1f0c682af61f7d7893f3f610c72c2847c76d00b841237e99bb5c44c2b2cd5b"));
        assert_eq!(eip191_hash_message(msg), hash);
    }

    #[test]
    fn sha3_hasher() {
        let expected = b256!("644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938");
        assert_eq!(sha3("hello world"), expected);

        let mut hasher = Sha3::new();
        hasher.update(b"hello");
        hasher.update(b" world");

        assert_eq!(hasher.clone().finalize(), expected);

        let mut hash = [0u8; 32];
        hasher.clone().finalize_into(&mut hash);
        assert_eq!(hash, expected);

        let mut hash = [0u8; 32];
        hasher.clone().finalize_into_array(&mut hash);
        assert_eq!(hash, expected);

        let mut hash = [0u8; 32];
        unsafe { hasher.finalize_into_raw(hash.as_mut_ptr()) };
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_try_boxing() {
        let x = Box::new(42);
        let y = box_try_new(42).unwrap();
        assert_eq!(x, y);

        let x = vec![1; 3];
        let y = try_vec![1; 3].unwrap();
        assert_eq!(x, y);

        let x = vec![1, 2, 3];
        let y = try_vec![1, 2, 3].unwrap();
        assert_eq!(x, y);
    }
}

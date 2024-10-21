use alloy_primitives::B256;
use core::mem::MaybeUninit;
use tiny_keccak::Hasher as _;
use core::fmt;

fn main() {}

/// Simple [`Keccak-256`] hasher.
///
/// Note that the "native-keccak" feature is not supported for this struct, and will default to the
/// [`tiny_keccak`] implementation.
///
/// [`Keccak-256`]: https://en.wikipedia.org/wiki/SHA-3
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

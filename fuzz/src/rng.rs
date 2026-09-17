//! Deterministic random number generators, so every fuzz input replays
//! exactly.  Neither is cryptographically secure; the `TryCryptoRng` marker
//! only lets the engine and the CTAPHID host accept them.

use rand_core::{Infallible, TryCryptoRng, TryRng};

/// SplitMix64.
#[derive(Clone, Debug)]
pub struct SplitMix(pub u64);

impl SplitMix {
    fn step(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

impl TryRng for SplitMix {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.step() as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self.step())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.step().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

impl TryCryptoRng for SplitMix {}

/// Channel identifiers for the CTAPHID host drawn from a narrow range, with
/// the reserved identifiers 0 and 0xffffffff mixed in, so a short input
/// reaches allocation collisions, the retry limit and the channel table limit.
#[derive(Clone, Debug)]
pub struct NarrowRng {
    inner: SplitMix,
    range: u32,
}

impl NarrowRng {
    /// Values below `range` (at least 1), plus the reserved identifiers.
    pub fn new(seed: u64, range: u32) -> Self {
        Self {
            inner: SplitMix(seed),
            range: range.max(1),
        }
    }
}

impl TryRng for NarrowRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let value = self.inner.step();
        Ok(match value % 64 {
            0 => 0,
            1 => u32::MAX,
            _ => ((value >> 8) % u64::from(self.range)) as u32,
        })
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(u64::from(self.try_next_u32()?))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        self.inner.try_fill_bytes(dest)
    }
}

impl TryCryptoRng for NarrowRng {}

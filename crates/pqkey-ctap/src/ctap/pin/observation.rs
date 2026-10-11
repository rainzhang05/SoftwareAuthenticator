//! Private observations proving persistence failures stop before verification.

#[derive(Clone, Copy)]
pub(crate) enum Phase {
    Decryption,
    Comparison,
    Token,
}

thread_local! {
    static COUNTS: std::cell::Cell<[usize; 3]> = const { std::cell::Cell::new([0; 3]) };
}

pub(crate) fn record(phase: Phase) {
    COUNTS.with(|counts| {
        let mut next = counts.get();
        next[phase as usize] += 1;
        counts.set(next);
    });
}

pub(crate) fn take() -> [usize; 3] {
    COUNTS.with(|counts| counts.replace([0; 3]))
}

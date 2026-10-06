//! A client for the running key, as a security key's management application
//! is one: it talks CTAP2 over CTAPHID to the key's platform client link,
//! so every
//! change goes through the same commands, checks and PIN rules as a
//! browser's.

pub mod ctap2;
pub mod ctaphid;

#[cfg(test)]
pub(crate) mod tests;

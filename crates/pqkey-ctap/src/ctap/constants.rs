//! CTAP command codes and authenticator status (error) codes.
//!
//! The status codes below are transcribed from the FIDO Alliance
//! "Client to Authenticator Protocol (CTAP)" v2.1, Proposed Standard, 2021-06-15,
//! § 8.2 "Status codes" (anchor `#error-responses`):
//! <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#error-responses>
//!
//! Command codes come from § 6 of the same document.
//!
//! These values are wire-visible: a wrong number is silently reported to the client
//! platform as a *different* error, so every status code here is pinned to its spec
//! literal by the `tests` module at the bottom of this file. That module also proves
//! no two distinct status codes share a value, which is the check that would have
//! caught `CTAP1_ERR_INVALID_PARAMETER` being defined as `0x2D` (the value belonging
//! to `CTAP2_ERR_KEEPALIVE_CANCEL`).
//!
//! When adding a status code, copy the value straight out of the § 8.2 table and add
//! a matching row to `STATUS_CODES` in the test module.

// Each constant carries the name the specification gives the value, which is
// its documentation; the module header says where to look them up.
#![allow(missing_docs)]

// -- Command codes (CTAP 2.1 § 6) --------------------------------------------

pub const CTAP_CMD_MAKE_CREDENTIAL: u8 = 0x01;
pub const CTAP_CMD_GET_ASSERTION: u8 = 0x02;
pub const CTAP_CMD_GET_INFO: u8 = 0x04;
pub const CTAP_CMD_CLIENT_PIN: u8 = 0x06;
pub const CTAP_CMD_RESET: u8 = 0x07;
pub const CTAP_CMD_GET_NEXT_ASSERTION: u8 = 0x08;
/// `authenticatorBioEnrollment`, CTAP 2.3 § 6.7.  Not implemented: this
/// authenticator has no biometric sensor.
pub const CTAP_CMD_BIO_ENROLLMENT: u8 = 0x09;
pub const CTAP_CMD_CREDENTIAL_MANAGEMENT: u8 = 0x0A;
/// `authenticatorSelection`, CTAP 2.3 § 6.9.
pub const CTAP_CMD_SELECTION: u8 = 0x0B;
/// Prototype `authenticatorBioEnrollment`, CTAP 2.3 § 6.12 (`FIDO_2_1_PRE`
/// backwards compatibility).  Not implemented either.
pub const CTAP_CMD_BIO_ENROLLMENT_PROTOTYPE: u8 = 0x40;

/// The longest response the engine produces, status byte included: the
/// largest CTAPHID message, 64 - 7 + 128 * (64 - 5) = 7609 bytes (CTAP 2.3
/// § 11.2.4), the transport the engine is served over.
pub const MAX_RESPONSE_SIZE: usize = 7609;

// -- Status codes (CTAP 2.1 § 8.2) -------------------------------------------
//
// Ordered by value so the table can be diffed against the spec by eye.

/// `0x00` is `CTAP2_OK` / `CTAP1_ERR_SUCCESS`: successful response.
pub const CTAP2_OK: u8 = 0x00;

pub const CTAP1_ERR_INVALID_COMMAND: u8 = 0x01;
pub const CTAP1_ERR_INVALID_PARAMETER: u8 = 0x02;
pub const CTAP1_ERR_INVALID_LENGTH: u8 = 0x03;
pub const CTAP1_ERR_INVALID_SEQ: u8 = 0x04;
pub const CTAP1_ERR_TIMEOUT: u8 = 0x05;
pub const CTAP1_ERR_CHANNEL_BUSY: u8 = 0x06;

pub const CTAP2_ERR_CBOR_UNEXPECTED_TYPE: u8 = 0x11;
pub const CTAP2_ERR_INVALID_CBOR: u8 = 0x12;
pub const CTAP2_ERR_MISSING_PARAMETER: u8 = 0x14;
pub const CTAP2_ERR_LIMIT_EXCEEDED: u8 = 0x15;
pub const CTAP2_ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;
pub const CTAP2_ERR_PROCESSING: u8 = 0x21;
pub const CTAP2_ERR_INVALID_CREDENTIAL: u8 = 0x22;
pub const CTAP2_ERR_USER_ACTION_PENDING: u8 = 0x23;
pub const CTAP2_ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
pub const CTAP2_ERR_OPERATION_DENIED: u8 = 0x27;
pub const CTAP2_ERR_KEY_STORE_FULL: u8 = 0x28;
pub const CTAP2_ERR_UNSUPPORTED_OPTION: u8 = 0x2B;
pub const CTAP2_ERR_INVALID_OPTION: u8 = 0x2C;
pub const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2D;
pub const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2E;
pub const CTAP2_ERR_USER_ACTION_TIMEOUT: u8 = 0x2F;
pub const CTAP2_ERR_NOT_ALLOWED: u8 = 0x30;
pub const CTAP2_ERR_PIN_INVALID: u8 = 0x31;
pub const CTAP2_ERR_PIN_BLOCKED: u8 = 0x32;
pub const CTAP2_ERR_PIN_AUTH_INVALID: u8 = 0x33;
pub const CTAP2_ERR_PIN_AUTH_BLOCKED: u8 = 0x34;
pub const CTAP2_ERR_PIN_NOT_SET: u8 = 0x35;
pub const CTAP2_ERR_PUAT_REQUIRED: u8 = 0x36;
pub const CTAP2_ERR_PIN_POLICY_VIOLATION: u8 = 0x37;
// 0x38 is Reserved for Future Use.
pub const CTAP2_ERR_REQUEST_TOO_LARGE: u8 = 0x39;
pub const CTAP2_ERR_ACTION_TIMEOUT: u8 = 0x3A;
/// Note `0x3B`, not `0x39`: `0x39` is [`CTAP2_ERR_REQUEST_TOO_LARGE`].
pub const CTAP2_ERR_UP_REQUIRED: u8 = 0x3B;
/// "The requested subcommand is either invalid or not implemented." Required
/// for any subcommand a command does not implement (CTAP 2.3 § 8.1).
pub const CTAP2_ERR_INVALID_SUBCOMMAND: u8 = 0x3E;
pub const CTAP2_ERR_UNAUTHORIZED_PERMISSION: u8 = 0x40;
pub const CTAP1_ERR_OTHER: u8 = 0x7F;

#[cfg(test)]
mod tests {
    use super::*;

    /// Every status code defined in this module, paired with its name.
    ///
    /// Keep this in sync with the constants above: the uniqueness test is only as
    /// good as this table's coverage.
    const STATUS_CODES: &[(&str, u8)] = &[
        ("CTAP2_OK", CTAP2_OK),
        ("CTAP1_ERR_INVALID_COMMAND", CTAP1_ERR_INVALID_COMMAND),
        ("CTAP1_ERR_INVALID_PARAMETER", CTAP1_ERR_INVALID_PARAMETER),
        ("CTAP1_ERR_INVALID_LENGTH", CTAP1_ERR_INVALID_LENGTH),
        ("CTAP1_ERR_INVALID_SEQ", CTAP1_ERR_INVALID_SEQ),
        ("CTAP1_ERR_TIMEOUT", CTAP1_ERR_TIMEOUT),
        ("CTAP1_ERR_CHANNEL_BUSY", CTAP1_ERR_CHANNEL_BUSY),
        (
            "CTAP2_ERR_CBOR_UNEXPECTED_TYPE",
            CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
        ),
        ("CTAP2_ERR_INVALID_CBOR", CTAP2_ERR_INVALID_CBOR),
        ("CTAP2_ERR_MISSING_PARAMETER", CTAP2_ERR_MISSING_PARAMETER),
        ("CTAP2_ERR_LIMIT_EXCEEDED", CTAP2_ERR_LIMIT_EXCEEDED),
        (
            "CTAP2_ERR_CREDENTIAL_EXCLUDED",
            CTAP2_ERR_CREDENTIAL_EXCLUDED,
        ),
        ("CTAP2_ERR_PROCESSING", CTAP2_ERR_PROCESSING),
        ("CTAP2_ERR_INVALID_CREDENTIAL", CTAP2_ERR_INVALID_CREDENTIAL),
        (
            "CTAP2_ERR_USER_ACTION_PENDING",
            CTAP2_ERR_USER_ACTION_PENDING,
        ),
        (
            "CTAP2_ERR_UNSUPPORTED_ALGORITHM",
            CTAP2_ERR_UNSUPPORTED_ALGORITHM,
        ),
        ("CTAP2_ERR_OPERATION_DENIED", CTAP2_ERR_OPERATION_DENIED),
        ("CTAP2_ERR_KEY_STORE_FULL", CTAP2_ERR_KEY_STORE_FULL),
        ("CTAP2_ERR_UNSUPPORTED_OPTION", CTAP2_ERR_UNSUPPORTED_OPTION),
        ("CTAP2_ERR_INVALID_OPTION", CTAP2_ERR_INVALID_OPTION),
        ("CTAP2_ERR_KEEPALIVE_CANCEL", CTAP2_ERR_KEEPALIVE_CANCEL),
        ("CTAP2_ERR_NO_CREDENTIALS", CTAP2_ERR_NO_CREDENTIALS),
        (
            "CTAP2_ERR_USER_ACTION_TIMEOUT",
            CTAP2_ERR_USER_ACTION_TIMEOUT,
        ),
        ("CTAP2_ERR_NOT_ALLOWED", CTAP2_ERR_NOT_ALLOWED),
        ("CTAP2_ERR_PIN_INVALID", CTAP2_ERR_PIN_INVALID),
        ("CTAP2_ERR_PIN_BLOCKED", CTAP2_ERR_PIN_BLOCKED),
        ("CTAP2_ERR_PIN_AUTH_INVALID", CTAP2_ERR_PIN_AUTH_INVALID),
        ("CTAP2_ERR_PIN_AUTH_BLOCKED", CTAP2_ERR_PIN_AUTH_BLOCKED),
        ("CTAP2_ERR_PIN_NOT_SET", CTAP2_ERR_PIN_NOT_SET),
        ("CTAP2_ERR_PUAT_REQUIRED", CTAP2_ERR_PUAT_REQUIRED),
        (
            "CTAP2_ERR_PIN_POLICY_VIOLATION",
            CTAP2_ERR_PIN_POLICY_VIOLATION,
        ),
        ("CTAP2_ERR_REQUEST_TOO_LARGE", CTAP2_ERR_REQUEST_TOO_LARGE),
        ("CTAP2_ERR_ACTION_TIMEOUT", CTAP2_ERR_ACTION_TIMEOUT),
        ("CTAP2_ERR_UP_REQUIRED", CTAP2_ERR_UP_REQUIRED),
        ("CTAP2_ERR_INVALID_SUBCOMMAND", CTAP2_ERR_INVALID_SUBCOMMAND),
        (
            "CTAP2_ERR_UNAUTHORIZED_PERMISSION",
            CTAP2_ERR_UNAUTHORIZED_PERMISSION,
        ),
        ("CTAP1_ERR_OTHER", CTAP1_ERR_OTHER),
    ];

    /// Each status code must equal the literal printed in CTAP 2.1 § 8.2.
    ///
    /// Written as literals on purpose: comparing a constant to itself proves nothing,
    /// so the right-hand sides are transcribed by hand from the spec table.
    #[test]
    fn status_codes_match_ctap21_spec_table() {
        assert_eq!(CTAP2_OK, 0x00);
        assert_eq!(CTAP1_ERR_INVALID_COMMAND, 0x01);
        assert_eq!(CTAP1_ERR_INVALID_PARAMETER, 0x02);
        assert_eq!(CTAP1_ERR_INVALID_LENGTH, 0x03);
        assert_eq!(CTAP1_ERR_INVALID_SEQ, 0x04);
        assert_eq!(CTAP1_ERR_TIMEOUT, 0x05);
        assert_eq!(CTAP1_ERR_CHANNEL_BUSY, 0x06);
        assert_eq!(CTAP2_ERR_CBOR_UNEXPECTED_TYPE, 0x11);
        assert_eq!(CTAP2_ERR_INVALID_CBOR, 0x12);
        assert_eq!(CTAP2_ERR_MISSING_PARAMETER, 0x14);
        assert_eq!(CTAP2_ERR_LIMIT_EXCEEDED, 0x15);
        assert_eq!(CTAP2_ERR_CREDENTIAL_EXCLUDED, 0x19);
        assert_eq!(CTAP2_ERR_PROCESSING, 0x21);
        assert_eq!(CTAP2_ERR_INVALID_CREDENTIAL, 0x22);
        assert_eq!(CTAP2_ERR_USER_ACTION_PENDING, 0x23);
        assert_eq!(CTAP2_ERR_UNSUPPORTED_ALGORITHM, 0x26);
        assert_eq!(CTAP2_ERR_OPERATION_DENIED, 0x27);
        assert_eq!(CTAP2_ERR_KEY_STORE_FULL, 0x28);
        assert_eq!(CTAP2_ERR_UNSUPPORTED_OPTION, 0x2B);
        assert_eq!(CTAP2_ERR_INVALID_OPTION, 0x2C);
        assert_eq!(CTAP2_ERR_KEEPALIVE_CANCEL, 0x2D);
        assert_eq!(CTAP2_ERR_NO_CREDENTIALS, 0x2E);
        assert_eq!(CTAP2_ERR_USER_ACTION_TIMEOUT, 0x2F);
        assert_eq!(CTAP2_ERR_NOT_ALLOWED, 0x30);
        assert_eq!(CTAP2_ERR_PIN_INVALID, 0x31);
        assert_eq!(CTAP2_ERR_PIN_BLOCKED, 0x32);
        assert_eq!(CTAP2_ERR_PIN_AUTH_INVALID, 0x33);
        assert_eq!(CTAP2_ERR_PIN_AUTH_BLOCKED, 0x34);
        assert_eq!(CTAP2_ERR_PIN_NOT_SET, 0x35);
        assert_eq!(CTAP2_ERR_PUAT_REQUIRED, 0x36);
        assert_eq!(CTAP2_ERR_PIN_POLICY_VIOLATION, 0x37);
        assert_eq!(CTAP2_ERR_REQUEST_TOO_LARGE, 0x39);
        assert_eq!(CTAP2_ERR_ACTION_TIMEOUT, 0x3A);
        assert_eq!(CTAP2_ERR_UP_REQUIRED, 0x3B);
        assert_eq!(CTAP2_ERR_INVALID_SUBCOMMAND, 0x3E);
        assert_eq!(CTAP2_ERR_UNAUTHORIZED_PERMISSION, 0x40);
        assert_eq!(CTAP1_ERR_OTHER, 0x7F);
    }

    /// No two distinct status codes may share a value.
    ///
    /// This is the regression test for the original bug: `CTAP1_ERR_INVALID_PARAMETER`
    /// and `CTAP2_ERR_KEEPALIVE_CANCEL` were both `0x2D`, so every invalid-parameter
    /// rejection reached the client platform labelled "keepalive cancel".
    #[test]
    fn status_codes_are_unique() {
        let mut collisions = Vec::new();
        for (index, (name, value)) in STATUS_CODES.iter().enumerate() {
            for (other_name, other_value) in &STATUS_CODES[index + 1..] {
                if value == other_value {
                    collisions.push(format!("{name} and {other_name} are both {value:#04X}"));
                }
            }
        }
        assert!(
            collisions.is_empty(),
            "status codes must be distinct, found: {}",
            collisions.join("; ")
        );
    }

    /// Guard against a constant being added above but forgotten in `STATUS_CODES`,
    /// which would silently weaken `status_codes_are_unique`.
    #[test]
    fn status_code_table_covers_every_constant() {
        let source = include_str!("constants.rs");
        let declared: Vec<&str> = source
            .lines()
            .filter_map(|line| line.trim().strip_prefix("pub const "))
            .filter_map(|rest| rest.split(':').next())
            .filter(|name| name.starts_with("CTAP1_ERR_") || name.starts_with("CTAP2_"))
            .collect();

        assert!(
            !declared.is_empty(),
            "failed to parse any status-code declarations out of constants.rs"
        );
        for name in declared {
            assert!(
                STATUS_CODES.iter().any(|(listed, _)| *listed == name),
                "{name} is declared but missing from STATUS_CODES"
            );
        }
    }

    /// Command codes come from CTAP 2.1 § 6; pinned for the same reason.
    #[test]
    fn command_codes_match_ctap21_spec() {
        assert_eq!(CTAP_CMD_MAKE_CREDENTIAL, 0x01);
        assert_eq!(CTAP_CMD_GET_ASSERTION, 0x02);
        assert_eq!(CTAP_CMD_GET_INFO, 0x04);
        assert_eq!(CTAP_CMD_CLIENT_PIN, 0x06);
        assert_eq!(CTAP_CMD_RESET, 0x07);
        assert_eq!(CTAP_CMD_GET_NEXT_ASSERTION, 0x08);
        assert_eq!(CTAP_CMD_BIO_ENROLLMENT, 0x09);
        assert_eq!(CTAP_CMD_CREDENTIAL_MANAGEMENT, 0x0A);
        assert_eq!(CTAP_CMD_SELECTION, 0x0B);
        // § 6.12 prototype command.
        assert_eq!(CTAP_CMD_BIO_ENROLLMENT_PROTOTYPE, 0x40);
    }
}

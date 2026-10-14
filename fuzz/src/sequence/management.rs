//! Independent model of management authorization and the two cursor grants.
use super::*;

#[derive(Clone)]
struct Grant {
    protocol: ClassicPinProtocol,
    persistent: bool,
    value: Zeroizing<[u8; 32]>,
    permissions: u8,
    rp: Option<String>,
    legacy: bool,
    verified: bool,
    used: bool,
    issued_at: Duration,
    id: u64,
}
struct Cursor<T> {
    token: u64,
    persistent: bool,
    protocol: ClassicPinProtocol,
    legacy: bool,
    entries: Vec<T>,
    index: usize,
}
#[derive(Default)]
pub(super) struct Oracle {
    grant: Option<Grant>,
    persistent: [Option<Grant>; 2],
    issued: u64,
    family: Option<u8>,
    context: Option<(bool, ClassicPinProtocol, u64)>,
    rps: Option<Cursor<String>>,
    credentials: Option<Cursor<Vec<u8>>>,
    rp_hash: Vec<u8>,
}
impl Oracle {
    pub(super) fn issue(
        &mut self,
        protocol: ClassicPinProtocol,
        value: [u8; 32],
        permissions: u8,
        rp: Option<String>,
        legacy: bool,
        now: Duration,
    ) {
        self.issued = self.issued.wrapping_add(1);
        let grant = Grant {
            protocol,
            persistent: permissions == 0x40,
            value: Zeroizing::new(value),
            permissions,
            rp,
            legacy,
            verified: true,
            used: false,
            issued_at: now,
            id: self.issued,
        };
        if grant.persistent {
            let slot = &mut self.persistent[usize::from(protocol.identifier() == 2)];
            if let Some(preceding) = slot.as_ref() {
                assert!(
                    preceding.value.as_slice() == grant.value.as_slice(),
                    "persistent issuance rotated without an authority transition"
                );
            }
            *slot = Some(grant);
        } else {
            self.grant = Some(grant);
        }
        self.rps = None;
        self.credentials = None;
    }
    pub(super) fn invalidate(&mut self) {
        self.grant = None;
        self.persistent = [None, None];
        self.rps = None;
        self.credentials = None;
    }
    pub(super) fn restart(&mut self) {
        self.grant = None;
        self.family = None;
        self.context = None;
        self.rps = None;
        self.credentials = None;
        self.rp_hash.clear();
    }
    fn observe_time(&mut self, now: Duration) {
        if self.grant.as_ref().is_some_and(|g| {
            let elapsed = now.saturating_sub(g.issued_at);
            elapsed >= Duration::from_secs(600) || (!g.used && elapsed >= Duration::from_secs(30))
        }) {
            self.grant = None;
        }
    }
    fn mac(&mut self, protocol: Option<&Value>, param: Option<&Value>, message: &[u8]) -> bool {
        let Some(g) = &mut self.grant else {
            return false;
        };
        if protocol != Some(&protocol_value(g.protocol)) {
            return false;
        }
        let Some(Value::Bytes(mac)) = param else {
            return false;
        };
        if *mac != authenticate(g.protocol, &g.value[..], message) {
            return false;
        }
        g.used = true;
        true
    }
    fn authorized(&self, family: u8, rp: Option<&[u8]>) -> bool {
        self.grant.as_ref().is_some_and(|g| {
            if !g.verified {
                return false;
            }
            if g.legacy {
                return family == CTAP_CMD_CREDENTIAL_MANAGEMENT_PROTOTYPE && g.rp.is_none();
            }
            g.permissions & 4 != 0
                && match &g.rp {
                    None => true,
                    Some(binding) => {
                        rp.is_some_and(|hash| Sha256::digest(binding.as_bytes()).as_slice() == hash)
                    }
                }
        })
    }
    fn cursor_valid<T>(&self, cursor: &Option<Cursor<T>>, family: u8, rp: Option<&[u8]>) -> bool {
        cursor.as_ref().is_some_and(|c| {
            if c.persistent {
                return family == CTAP_CMD_CREDENTIAL_MANAGEMENT
                    && self.persistent[usize::from(c.protocol.identifier() == 2)]
                        .as_ref()
                        .is_some_and(|g| g.id == c.token);
            }
            self.grant
                .as_ref()
                .is_some_and(|g| c.token == g.id && c.legacy == g.legacy)
                && self.authorized(family, rp)
        })
    }
    /// Run before the parent observes successful data mutations. Rejected
    /// requests must never advance the independent credential data model.
    pub(super) fn check(
        &mut self,
        request: &[u8],
        response: &[u8],
        credentials: &[Credential],
        now: Duration,
    ) {
        self.observe_time(now);
        let Some(&code) = request.first() else {
            return;
        };
        let parameters = match CtapApp::decode_request_parameters(&request[1..]) {
            Some(Value::Map(p)) => p,
            _ => Vec::new(),
        };
        let success = status(response) == CTAP2_OK;
        if matches!(
            code,
            CTAP_CMD_CREDENTIAL_MANAGEMENT | CTAP_CMD_CREDENTIAL_MANAGEMENT_PROTOTYPE
        ) {
            if self.family != Some(code) {
                self.family = Some(code);
                self.rps = None;
                self.credentials = None;
            }
            let sub = unsigned(get_int(&parameters, 1)).unwrap_or(0);
            let params = match get_int(&parameters, 2) {
                Some(Value::Map(p)) => p.as_slice(),
                _ => &[],
            };
            let rp_hash = match get_int(params, 1) {
                Some(Value::Bytes(b)) => Some(b.as_slice()),
                _ => None,
            };
            let mut selected_persistent = None;
            if code == CTAP_CMD_CREDENTIAL_MANAGEMENT && matches!(sub, 1 | 2 | 4) {
                let mut message = vec![sub as u8];
                if sub == 4
                    && let Some(params) = get_int(&parameters, 2)
                {
                    message.extend(cbor::encode(params));
                }
                selected_persistent = self
                    .persistent
                    .iter()
                    .flatten()
                    .find(|g| {
                        get_int(&parameters, 3) == Some(&protocol_value(g.protocol))
                            && get_int(&parameters, 4)
                                == Some(&bytes(&authenticate(g.protocol, &g.value[..], &message)))
                    })
                    .cloned();
            }
            if matches!(sub, 3 | 5) {
                let valid = if sub == 3 {
                    self.cursor_valid(&self.rps, code, None)
                } else {
                    self.cursor_valid(&self.credentials, code, Some(&self.rp_hash))
                };
                if !valid {
                    assert!(!success, "management continuation bypassed its grant");
                    if sub == 3 {
                        self.rps = None;
                    } else {
                        self.credentials = None;
                    }
                    return;
                }
            } else {
                let mandatory = match sub {
                    4 => get_int(params, 1).is_some(),
                    6 => get_int(params, 2).is_some(),
                    7 => get_int(params, 2).is_some() && get_int(params, 3).is_some(),
                    1 | 2 => true,
                    _ => false,
                };
                let mut message = vec![sub as u8];
                if !matches!(sub, 1 | 2)
                    && let Some(value) = get_int(&parameters, 2)
                {
                    message.extend(cbor::encode(value));
                }
                let mac = mandatory
                    && (selected_persistent.is_some()
                        || self.mac(get_int(&parameters, 3), get_int(&parameters, 4), &message));
                let mutation_rp = match get_int(params, 2) {
                    Some(Value::Map(desc)) => match get_text(desc, "id") {
                        Some(Value::Bytes(id)) => credentials
                            .iter()
                            .find(|c| c.id == *id)
                            .map(|c| c.application.to_vec()),
                        _ => None,
                    },
                    _ => None,
                };
                let target = if matches!(sub, 6 | 7) {
                    mutation_rp.as_deref()
                } else {
                    rp_hash
                };
                if success {
                    assert!(
                        mac && (selected_persistent.is_some() || self.authorized(code, target)),
                        "management bypassed MAC, provenance, permissions or scope"
                    );
                }
            }
            if !success {
                return;
            }
            let body = decode_map(&response[1..]).unwrap_or_default();
            let grant = if matches!(sub, 3 | 5) {
                None
            } else {
                selected_persistent.as_ref().or(self.grant.as_ref())
            };
            if let Some(grant) = grant {
                let context = (grant.persistent, grant.protocol, grant.id);
                if self.context != Some(context) {
                    self.rps = None;
                    self.credentials = None;
                    self.context = Some(context);
                }
            }
            match sub {
                1 => assert_eq!(
                    get_int(&body, 1),
                    Some(&int(
                        credentials.iter().filter(|c| c.discoverable).count() as i64
                    ))
                ),
                2 => {
                    let mut entries: Vec<_> = credentials
                        .iter()
                        .filter(|c| c.discoverable)
                        .map(|c| c.rp_id.clone())
                        .collect();
                    entries.sort();
                    entries.dedup();
                    assert_eq!(get_int(&body, 5), Some(&int(entries.len() as i64)));
                    assert_eq!(
                        get_int(&body, 4),
                        Some(&bytes(&Sha256::digest(entries[0].as_bytes())))
                    );
                    self.rps = Some(Cursor {
                        token: grant.unwrap().id,
                        persistent: grant.unwrap().persistent,
                        protocol: grant.unwrap().protocol,
                        legacy: grant.unwrap().legacy,
                        entries,
                        index: 1,
                    });
                }
                3 => {
                    let cursor = self.rps.as_mut().unwrap();
                    let rp = cursor
                        .entries
                        .get(cursor.index)
                        .expect("exhausted RP cursor succeeded");
                    assert_eq!(
                        get_int(&body, 4),
                        Some(&bytes(&Sha256::digest(rp.as_bytes())))
                    );
                    cursor.index += 1;
                }
                4 => {
                    let hash = rp_hash.unwrap();
                    let entries: Vec<_> = credentials
                        .iter()
                        .rev()
                        .filter(|c| c.discoverable && c.application.as_slice() == hash)
                        .map(|c| c.id.clone())
                        .collect();
                    assert_eq!(get_int(&body, 9), Some(&int(entries.len() as i64)));
                    check_id(&body, entries.first().expect("empty enumeration succeeded"));
                    self.rp_hash = hash.to_vec();
                    self.credentials = Some(Cursor {
                        token: grant.unwrap().id,
                        persistent: grant.unwrap().persistent,
                        protocol: grant.unwrap().protocol,
                        legacy: grant.unwrap().legacy,
                        entries,
                        index: 1,
                    });
                }
                5 => {
                    let cursor = self.credentials.as_mut().unwrap();
                    while cursor
                        .entries
                        .get(cursor.index)
                        .is_some_and(|id| !credentials.iter().any(|c| c.id == *id))
                    {
                        cursor.index += 1;
                    }
                    check_id(
                        &body,
                        cursor
                            .entries
                            .get(cursor.index)
                            .expect("exhausted credential cursor succeeded"),
                    );
                    cursor.index += 1;
                }
                6 => {
                    self.rps = None;
                    self.credentials = None;
                }
                _ => {}
            }
        } else if matches!(code, CTAP_CMD_MAKE_CREDENTIAL | CTAP_CMD_GET_ASSERTION) {
            let (auth_key, protocol_key, hash_key) = if code == CTAP_CMD_MAKE_CREDENTIAL {
                (8, 9, 1)
            } else {
                (6, 7, 2)
            };
            if let Some(Value::Bytes(hash)) = get_int(&parameters, hash_key)
                && self.mac(
                    get_int(&parameters, protocol_key),
                    get_int(&parameters, auth_key),
                    hash,
                )
                && let Some(g) = &mut self.grant
            {
                let permission = if code == CTAP_CMD_MAKE_CREDENTIAL {
                    1
                } else {
                    2
                };
                let rp = if code == CTAP_CMD_MAKE_CREDENTIAL {
                    match get_int(&parameters, 2) {
                        Some(Value::Map(rp)) => get_text(rp, "id"),
                        _ => None,
                    }
                } else {
                    get_int(&parameters, 1)
                };
                if let Some(Value::Text(rp)) = rp
                    && g.permissions & permission != 0
                    && g.verified
                    && g.rp.as_ref().is_none_or(|bound| bound == rp)
                {
                    g.rp = Some(rp.clone());
                }
            }
            if success
                && let Some(Value::Bytes(data)) =
                    decode_map(&response[1..]).and_then(|b| get_int(&b, 2).cloned())
                && data.get(32).is_some_and(|flag| flag & 1 != 0)
                && let Some(g) = &mut self.grant
            {
                g.verified = false;
                g.legacy = false;
                g.permissions &= 0x10;
            }
        } else if code == CTAP_CMD_AUTHENTICATOR_CONFIG {
            if let Some(sub) = unsigned(get_int(&parameters, 1)) {
                let mut message = vec![0xff; 32];
                message.extend([code, sub as u8]);
                if let Some(params) = get_int(&parameters, 2) {
                    message.extend(cbor::encode(params));
                }
                self.mac(get_int(&parameters, 3), get_int(&parameters, 4), &message);
            }
        } else if code == CTAP_CMD_LARGE_BLOBS {
            if let (Some(Value::Bytes(fragment)), Some(offset)) =
                (get_int(&parameters, 2), unsigned(get_int(&parameters, 3)))
            {
                let mut message = vec![0xff; 32];
                message.extend([code, 0]);
                message.extend((offset as u32).to_le_bytes());
                message.extend(Sha256::digest(fragment));
                self.mac(get_int(&parameters, 6), get_int(&parameters, 5), &message);
            }
        } else if success
            && code == CTAP_CMD_CLIENT_PIN
            && matches!(unsigned(get_int(&parameters, 2)), Some(3 | 4 | 5 | 9))
        {
            if matches!(unsigned(get_int(&parameters, 2)), Some(3 | 4)) {
                self.invalidate();
            } else {
                self.grant = None;
                self.rps = None;
                self.credentials = None;
            }
        } else if success && code == CTAP_CMD_RESET {
            self.invalidate();
            self.restart();
        }
    }
}
fn check_id(body: &[(Value, Value)], expected: &[u8]) {
    let Some(Value::Map(desc)) = get_int(body, 7) else {
        panic!("descriptor")
    };
    assert_eq!(get_text(desc, "id"), Some(&bytes(expected)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "management bypassed MAC, provenance, permissions or scope")]
    fn oracle_catches_an_unscoped_modern_mc_grant_misclassified_as_legacy() {
        let mut oracle = Oracle::default();
        let value = [0x41; 32];
        oracle.issue(
            ClassicPinProtocol::V2,
            value,
            1,
            None,
            false,
            Duration::ZERO,
        );
        let request = command(
            CTAP_CMD_CREDENTIAL_MANAGEMENT_PROTOTYPE,
            &Value::Map(vec![
                (int(1), int(1)),
                (int(3), int(2)),
                (
                    int(4),
                    bytes(&authenticate(ClassicPinProtocol::V2, &value, &[1])),
                ),
            ]),
        );
        oracle.check(&request, &[CTAP2_OK], &[], Duration::ZERO);
    }

    #[test]
    #[should_panic(expected = "management continuation bypassed its grant")]
    fn oracle_catches_success_without_a_cursor() {
        let mut oracle = Oracle::default();
        oracle.issue(
            ClassicPinProtocol::V1,
            [0x41; 32],
            3,
            None,
            true,
            Duration::ZERO,
        );
        oracle.check(
            &command(
                CTAP_CMD_CREDENTIAL_MANAGEMENT_PROTOTYPE,
                &Value::Map(vec![(int(1), int(5))]),
            ),
            &[CTAP2_OK],
            &[],
            Duration::ZERO,
        );
    }
}

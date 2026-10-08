//! Secrets must not survive in blocks surrendered to the global allocator.
#![warn(clippy::undocumented_unsafe_blocks)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    fs,
    hint::black_box,
    path::PathBuf,
    ptr, slice,
    sync::atomic::{AtomicPtr, Ordering},
};

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use p256::elliptic_curve::subtle::ConstantTimeEq;
use pqkey::allocator::WipingAllocator;
use pqkey_ctap::{
    ClassicPinProtocol, CoseAlg,
    ctap::{AttestationMode, CtapApp, InterruptFlag, constants::*, presence::AutoApprove},
    platform::{PlatformKeyAgreement, authenticate, pin_hash},
    rsa_fixture,
    rsa_fixture::PrivateValue,
    store::{
        AttestationRecord, CredentialRecord, CredentialStore, FileStore, MemoryStore,
        PinStateRecord, PrivateKeyMaterial,
    },
    try_credential_secret_from_bytes, try_sign_challenge, verify_signature,
};
use rand_core::{Infallible, TryCryptoRng, TryRng};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

struct Block {
    ptr: *mut u8,
    layout: Layout,
    next: *mut Block,
}

static FREED: AtomicPtr<Block> = AtomicPtr::new(ptr::null_mut());

struct RetainingAllocator;

// SAFETY: System supplies all blocks with the caller's layout. Deallocation
// transfers ownership to the list instead of releasing the storage. Nodes
// are allocated directly through System, without global allocator recursion.
unsafe impl GlobalAlloc for RetainingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's non-zero layout is passed through unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's non-zero layout is passed through unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: Block has a non-zero layout; this bypasses the global
        // allocator and gives the list its own suitably aligned node.
        let node = unsafe { System.alloc(Layout::new::<Block>()) }.cast::<Block>();
        if node.is_null() {
            // Losing a record would make the test pass without inspecting it.
            std::process::abort();
        }
        let mut next = FREED.load(Ordering::Acquire);
        loop {
            // SAFETY: this node is exclusively owned until it is published.
            // The surrendered block remains allocated in System for scanning.
            unsafe { node.write(Block { ptr, layout, next }) };
            match FREED.compare_exchange_weak(next, node, Ordering::Release, Ordering::Acquire) {
                Ok(_) => break,
                Err(head) => next = head,
            }
        }
    }
}

#[global_allocator]
static ALLOCATOR: WipingAllocator<RetainingAllocator> = WipingAllocator::new(RetainingAllocator);

/// The same scan is used for live controls and retained blocks. Entirely
/// zero blocks cannot contain a non-zero secret; skip window comparisons on
/// those blocks, since RSA generation releases many large allocations.
fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    assert!(!needle.is_empty() && needle.iter().any(|&byte| byte != 0));
    if bytes.iter().all(|&byte| byte == 0) {
        return false;
    }
    bytes
        .windows(needle.len())
        .any(|window| bool::from(window.ct_eq(needle)))
}

fn live_control(needle: &[u8]) {
    let layout = Layout::from_size_align(needle.len(), 8).unwrap();
    // SAFETY: the layout is non-zero. The successful allocation is fully
    // initialized before scanning, then surrendered with its original layout.
    unsafe {
        let ptr = std::alloc::alloc(layout);
        assert!(!ptr.is_null());
        ptr::copy_nonoverlapping(needle.as_ptr(), ptr, needle.len());
        assert!(contains(
            black_box(slice::from_raw_parts(ptr, needle.len())),
            black_box(needle)
        ));
        std::alloc::dealloc(ptr, layout);
    }
}

fn scan_freed(label: &str, needles: &[PrivateValue]) {
    let mut patterns = Vec::new();
    for needle in needles {
        let mut reversed = Zeroizing::new(needle.bytes.to_vec());
        reversed.reverse();
        live_control(&needle.bytes);
        live_control(&reversed);
        patterns.push((needle.name, &needle.bytes[..], reversed));
    }
    let mut blocks = 0;
    let mut bytes_scanned = 0;
    let mut node = FREED.swap(ptr::null_mut(), Ordering::AcqRel);
    while !node.is_null() {
        // SAFETY: swapping the list transfers ownership of all its nodes.
        // System has not freed their blocks, and the production wrapper wrote
        // every payload byte before surrendering them to this allocator.
        let block = unsafe { &*node };
        // SAFETY: block's pointer and layout describe retained, initialized
        // storage. It is read only until released directly through System.
        let bytes = unsafe { slice::from_raw_parts(block.ptr, block.layout.size()) };
        for (name, given, reversed) in &patterns {
            assert!(!contains(bytes, given), "{label}: {name} in a freed block");
            assert!(
                !contains(bytes, reversed),
                "{label}: reversed {name} in a freed block"
            );
        }
        assert!(
            bytes.iter().all(|&byte| byte == 0),
            "{label}: unwiped block"
        );
        blocks += 1;
        bytes_scanned += bytes.len();
        let next = block.next;
        // SAFETY: the scan is finished and all borrows end here. These blocks
        // and nodes came from System with these layouts; freeing them directly
        // avoids recording them again through the global allocator.
        unsafe {
            System.dealloc(block.ptr, block.layout);
            System.dealloc(node.cast(), Layout::new::<Block>());
        }
        node = next;
    }
    assert!(blocks > 0 && bytes_scanned > 0, "{label}: no freed blocks");
    println!("{label}: {blocks} freed blocks, {bytes_scanned} bytes, no secrets");
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("pqkey-heap-{name}"));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn exercise(alg: CoseAlg, material: PrivateKeyMaterial) {
    let mut needles = match &material {
        PrivateKeyMaterial::RsaPrimes { primes } => {
            rsa_fixture::private_values(primes).unwrap().secrets
        }
        PrivateKeyMaterial::P256Scalar { scalar } => vec![PrivateValue {
            name: "scalar",
            bytes: Zeroizing::new(scalar.to_vec()),
        }],
        PrivateKeyMaterial::Seed { seed } => vec![PrivateValue {
            name: "seed",
            bytes: Zeroizing::new(seed.to_vec()),
        }],
    };
    let blob: Vec<u8> = (0xd0..=0xef).collect();
    needles.push(PrivateValue {
        name: "credential blob",
        bytes: Zeroizing::new(blob.clone()),
    });
    let large_blob_key = core::array::from_fn(|index| 0xa0 + index as u8);
    needles.push(PrivateValue {
        name: "large-blob key",
        bytes: Zeroizing::new(large_blob_key.to_vec()),
    });
    {
        let dir = TempDir::new();
        let record = CredentialRecord {
            credential_id: vec![1; 33],
            rp_id: "example.com".into(),
            user_id: vec![2; 16],
            user_name: Some("alice".into()),
            user_display_name: None,
            alg,
            private_key: material,
            cred_random_with_uv: [0x33; 32],
            cred_random_without_uv: [0x44; 32],
            cred_blob: Some(blob),
            large_blob_key: Some(large_blob_key),
            cred_protect: 1,
            sign_count: 0,
            created_at: 0,
        };
        let (key, public) = record.keypair().unwrap();
        let stored = key.secret_bytes();
        let reread = try_credential_secret_from_bytes(alg, &stored).unwrap();
        for key in [&key, &reread] {
            let signature = try_sign_challenge(alg, key, &[0x11; 37], &[0x22; 32]).unwrap();
            verify_signature(alg, &public, &rsa_fixture::MESSAGE, &signature).unwrap();
        }
        let mut store = FileStore::open(&dir.0).unwrap();
        store.put(&record).unwrap();
        drop(store);
        let store = FileStore::open(&dir.0).unwrap();
        let mut loaded = store.get(&record.credential_id).unwrap().unwrap();
        // The store assigns creation order; every other field must survive.
        loaded.created_at = record.created_at;
        assert_eq!(loaded, record);
        let (loaded_key, loaded_public) = loaded.keypair().unwrap();
        assert_eq!(loaded_public, public);
        let signature = try_sign_challenge(alg, &loaded_key, &[0x11; 37], &[0x22; 32]).unwrap();
        verify_signature(alg, &loaded_public, &rsa_fixture::MESSAGE, &signature).unwrap();
    }
    scan_freed(alg.name(), &needles);
}

/// Every random array is recognizable to the scan, including the key made
/// by largeBlobKey. Private signing keys still use the operating system RNG.
struct CanaryRng;

impl TryRng for CanaryRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(u32::from_le_bytes([0xb3; 4]))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(u64::from_le_bytes([0xb3; 8]))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        dest.fill(0xb3);
        Ok(())
    }
}

impl TryCryptoRng for CanaryRng {}

fn int(value: i64) -> Value {
    Value::Integer(Integer::from(value))
}

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

fn member(value: &Value, key: i64) -> &Value {
    &value
        .as_map()
        .unwrap()
        .iter()
        .find(|(existing, _)| *existing == int(key))
        .unwrap()
        .1
}

fn engine_request(app: &mut CtapApp<'_>, command: u8, entries: Vec<(Value, Value)>) -> Value {
    let mut request = vec![command];
    into_writer(&Value::Map(entries), &mut request).unwrap();
    let response = app.call(&request);
    assert_eq!(response[0], CTAP2_OK);
    from_reader(&response[1..]).unwrap()
}

fn engine_token(
    app: &mut CtapApp<'_>,
    session: &PlatformKeyAgreement,
    key_agreement: &Value,
) -> Zeroizing<Vec<u8>> {
    let response = engine_request(
        app,
        CTAP_CMD_CLIENT_PIN,
        vec![
            (int(1), int(2)),
            (int(2), int(9)),
            (int(3), key_agreement.clone()),
            (
                int(6),
                Value::Bytes(session.encrypt(&pin_hash(b"1234")[..], [0x71; 16]).unwrap()),
            ),
            (int(9), int(0x07)),
            (int(10), text("example.com")),
        ],
    );
    session
        .decrypt(member(&response, 2).as_bytes().unwrap())
        .unwrap()
}

fn exercise_large_blob_key_responses() {
    let needles = [PrivateValue {
        name: "large-blob key",
        bytes: Zeroizing::new(vec![0xb3; 32]),
    }];
    {
        let mut store = MemoryStore::new();
        let mut pin_state = PinStateRecord::default();
        pin_state.pin_hash = Some(*pin_hash(b"1234"));
        store.set_pin_state(&pin_state).unwrap();
        // The first encoded attestation contains the key but cannot fit. Its
        // secret CBOR and serialization are discarded before self attestation.
        store
            .set_attestation(&AttestationRecord {
                private_key: [0x11; 32],
                certificate_chain: vec![vec![0x30; MAX_RESPONSE_SIZE]],
            })
            .unwrap();
        let interrupt = InterruptFlag::new();
        let mut app = CtapApp::new(store, CanaryRng, AutoApprove, &interrupt, [0; 16]);
        app.set_attestation_mode(AttestationMode::Certificate);
        let response = engine_request(
            &mut app,
            CTAP_CMD_CLIENT_PIN,
            vec![(int(1), int(2)), (int(2), int(2))],
        );
        let peer_key = member(&response, 1);
        let x: [u8; 32] = member(peer_key, -2).as_bytes().unwrap()[..]
            .try_into()
            .unwrap();
        let y: [u8; 32] = member(peer_key, -3).as_bytes().unwrap()[..]
            .try_into()
            .unwrap();
        let session =
            PlatformKeyAgreement::new(ClassicPinProtocol::V2, &x, &y, &[0x71; 32]).unwrap();
        let (x, y) = session.public_key();
        let key_agreement = Value::Map(vec![
            (int(1), int(2)),
            (int(3), int(-25)),
            (int(-1), int(1)),
            (int(-2), Value::Bytes(x.to_vec())),
            (int(-3), Value::Bytes(y.to_vec())),
        ]);
        let token = engine_token(&mut app, &session, &key_agreement);
        let hash = [0x44; 32];
        let extensions = Value::Map(vec![(text("largeBlobKey"), Value::Bool(true))]);
        let response = engine_request(
            &mut app,
            CTAP_CMD_MAKE_CREDENTIAL,
            vec![
                (int(1), Value::Bytes(hash.to_vec())),
                (int(2), Value::Map(vec![(text("id"), text("example.com"))])),
                (
                    int(3),
                    Value::Map(vec![(text("id"), Value::Bytes(vec![1]))]),
                ),
                (
                    int(4),
                    Value::Array(vec![Value::Map(vec![
                        (text("alg"), int(-7)),
                        (text("type"), text("public-key")),
                    ])]),
                ),
                (int(6), extensions.clone()),
                (int(7), Value::Map(vec![(text("rk"), Value::Bool(true))])),
                (
                    int(8),
                    Value::Bytes(authenticate(ClassicPinProtocol::V2, &token, &hash)),
                ),
                (int(9), int(2)),
            ],
        );
        assert!(bool::from(
            member(&response, 5).as_bytes().unwrap()[..].ct_eq(&needles[0].bytes)
        ));
        assert!(
            !member(&response, 3)
                .as_map()
                .unwrap()
                .iter()
                .any(|(key, _)| *key == text("x5c"))
        );
        let data = member(&response, 2).as_bytes().unwrap();
        let length = usize::from(u16::from_be_bytes([data[53], data[54]]));
        let descriptor = Value::Map(vec![
            (text("id"), Value::Bytes(data[55..55 + length].to_vec())),
            (text("type"), text("public-key")),
        ]);
        let token = engine_token(&mut app, &session, &key_agreement);
        let response = engine_request(
            &mut app,
            CTAP_CMD_GET_ASSERTION,
            vec![
                (int(1), text("example.com")),
                (int(2), Value::Bytes(hash.to_vec())),
                (int(3), Value::Array(vec![descriptor])),
                (int(4), extensions),
                (
                    int(6),
                    Value::Bytes(authenticate(ClassicPinProtocol::V2, &token, &hash)),
                ),
                (int(7), int(2)),
            ],
        );
        assert!(bool::from(
            member(&response, 7).as_bytes().unwrap()[..].ct_eq(&needles[0].bytes)
        ));
        let token = engine_token(&mut app, &session, &key_agreement);
        let params = Value::Map(vec![(
            int(1),
            Value::Bytes(Sha256::digest(b"example.com").to_vec()),
        )]);
        let mut message = vec![4];
        into_writer(&params, &mut message).unwrap();
        let response = engine_request(
            &mut app,
            CTAP_CMD_CREDENTIAL_MANAGEMENT,
            vec![
                (int(1), int(4)),
                (int(2), params),
                (int(3), int(2)),
                (
                    int(4),
                    Value::Bytes(authenticate(ClassicPinProtocol::V2, &token, &message)),
                ),
            ],
        );
        assert!(bool::from(
            member(&response, 11).as_bytes().unwrap()[..].ct_eq(&needles[0].bytes)
        ));
    }
    scan_freed("large-blob key responses", &needles);
}

fn main() {
    exercise(
        CoseAlg::RS256,
        PrivateKeyMaterial::try_generate(CoseAlg::RS256).unwrap(),
    );
    for alg in [CoseAlg::RS256, CoseAlg::PS256] {
        exercise(
            alg,
            PrivateKeyMaterial::RsaPrimes {
                primes: rsa_fixture::PRIMES,
            },
        );
    }
    for alg in [
        CoseAlg::ES256,
        CoseAlg::ES384,
        CoseAlg::EdDSA,
        CoseAlg::Ed448,
        CoseAlg::MLDSA65,
    ] {
        exercise(alg, PrivateKeyMaterial::try_generate(alg).unwrap());
    }
    exercise_large_blob_key_responses();
    // The last case's control buffers were dropped after its secret scan.
    // Inspect their retained blocks too, before the program exits.
    scan_freed("final cleanup", &[]);
    println!("heap residue: 9 cases passed, including live controls");
}

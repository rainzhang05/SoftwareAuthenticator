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

use p256::elliptic_curve::subtle::ConstantTimeEq;
use pqkey::allocator::WipingAllocator;
use pqkey_ctap::{
    CoseAlg, rsa_fixture,
    rsa_fixture::PrivateValue,
    store::{CredentialRecord, CredentialStore, FileStore, PrivateKeyMaterial},
    try_credential_secret_from_bytes, try_sign_challenge, verify_signature,
};
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
            large_blob_key: None,
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
    // The last case's control buffers were dropped after its secret scan.
    // Inspect their retained blocks too, before the program exits.
    scan_freed("final cleanup", &[]);
    println!("heap residue: 8 cases passed, including live controls");
}

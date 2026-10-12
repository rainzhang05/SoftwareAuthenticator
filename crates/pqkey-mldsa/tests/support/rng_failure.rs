//! Linux-only fault injection shared by the two standalone residue probes.
//! The filter applies only to this disposable child, never to the test parent.

pub fn is_child() -> bool {
    std::env::args().any(|arg| arg == "--rng-failure")
}

pub fn run_child() {
    assert!(
        std::process::Command::new(std::env::current_exe().expect("test executable"))
            .arg("--rng-failure")
            .status()
            .expect("RNG-failure child")
            .success(),
        "RNG-failure residue probe failed"
    );
}

pub fn block_getrandom() {
    // Resolve getrandom's libc backend before installing the filter. EIO is
    // fatal, unlike ENOSYS/EPERM, which can select a /dev/urandom fallback.
    getrandom::fill(&mut [0u8; 1]).expect("prime the OS RNG backend");
    let filter = [
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0, // seccomp_data.nr
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: libc::SYS_getrandom as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | libc::EIO as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr().cast_mut(),
    };
    // SAFETY: prctl's integer arguments have the required widths. The filter
    // and program remain live for the syscall, which copies them into the
    // kernel. This single-threaded child never switches syscall architectures.
    unsafe {
        assert_eq!(
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1usize, 0usize, 0usize, 0usize),
            0
        );
        assert_eq!(
            libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
            0
        );
    }
    assert_eq!(
        getrandom::fill(&mut [0u8; 1])
            .expect_err("getrandom must fail")
            .raw_os_error(),
        Some(libc::EIO)
    );
}

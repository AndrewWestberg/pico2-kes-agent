//! Host-only checks of the actual framing, memory protection and fixture boundaries.
use crate::{
    evidence::{self, Check, Verdict},
    fixture,
};
use kes_protocol::{management, usb};
use std::{
    io::Read,
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");

fn check(name: &'static str, expected: &'static str, ok: bool) -> Check {
    Check {
        name,
        expected,
        observed: if ok {
            "expected outcome"
        } else {
            "unexpected outcome"
        },
        executions: 1,
        passed: ok,
    }
}

fn command_check(
    name: &'static str,
    expected: &'static str,
    args: &[&str],
    deadline: Instant,
) -> Check {
    let mut result = Check {
        name,
        expected,
        observed: "unavailable",
        executions: 0,
        passed: false,
    };
    let mut command = Command::new("cargo");
    command
        .args(args)
        .current_dir(ROOT)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let Ok(mut child) = command.spawn() else {
        return result;
    };
    result.executions = 1;
    let pid = child.id() as i32;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                result.observed = if status.success() {
                    "successful exit"
                } else {
                    "failed exit"
                };
                result.passed = status.success();
                return result;
            }
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(50));
            }
            _ => {
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                result.observed = "deadline exceeded";
                return result;
            }
        }
    }
}

fn host_checks(deadline: Instant) -> Vec<Check> {
    [
        (
            "host-format",
            "workspace formatting check exits successfully",
            &["fmt", "--all", "--check"][..],
        ),
        (
            "host-check",
            "locked host check exits successfully",
            &["check", "--locked"][..],
        ),
        (
            "host-tests",
            "locked host tests exit successfully",
            &[
                "test",
                "--locked",
                "--workspace",
                "--exclude",
                "pico2-kes-firmware",
            ][..],
        ),
        (
            "host-clippy",
            "host lint exits successfully with warnings denied",
            &[
                "clippy",
                "--locked",
                "--workspace",
                "--exclude",
                "pico2-kes-firmware",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ][..],
        ),
        (
            "core-no-std",
            "core no std check exits successfully",
            &[
                "check",
                "--locked",
                "-p",
                "kes-core",
                "--no-default-features",
            ][..],
        ),
        (
            "protocol-no-std",
            "protocol no std check exits successfully",
            &[
                "check",
                "--locked",
                "-p",
                "kes-protocol",
                "--no-default-features",
            ][..],
        ),
    ]
    .into_iter()
    .map(|(name, expected, args)| command_check(name, expected, args, deadline))
    .collect()
}

fn usb_header(length: u32) -> [u8; usb::HEADER_LEN] {
    let mut h = [0; usb::HEADER_LEN];
    h[..4].copy_from_slice(b"PKA1");
    h[4..6].copy_from_slice(&usb::MAJOR.to_be_bytes());
    h[6..8].copy_from_slice(&(usb::Kind::Hello as u16).to_be_bytes());
    h[16..20].copy_from_slice(&length.to_be_bytes());
    h
}

fn codec_checks() -> Vec<Check> {
    let mut checks = Vec::new();
    let mut d = usb::Decoder::new();
    let mut h = usb_header(0);
    h[0] = 0;
    let malformed = matches!(d.feed(&h), Err(usb::Error::Magic))
        && matches!(d.feed(&[]), Err(usb::Error::Poisoned));
    checks.push(check("usb-malformed", "Magic then Poisoned", malformed));
    let mut d = usb::Decoder::new();
    let h = usb_header(4);
    let truncated = matches!(d.feed(&h[..10]), Ok((10, None))) && d.buffered_len() == 10;
    checks.push(check(
        "usb-truncated",
        "incomplete header and bounded buffer",
        truncated,
    ));
    let mut d = usb::Decoder::new();
    let h = usb_header((usb::MAX_PAYLOAD + 1) as u32);
    let oversized = matches!(d.feed(&h), Err(usb::Error::Length))
        && d.buffered_len() == usb::HEADER_LEN
        && std::mem::size_of::<usb::Decoder>() <= usb::MAX_FRAME + 64;
    checks.push(check(
        "usb-oversized",
        "Length before body buffering",
        oversized,
    ));
    let mut d = management::FrameDecoder::new();
    let payload = b"{";
    let mut frame = Vec::from((payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    let malformed = d.feed(&frame) == Ok(frame.len())
        && d.frame().is_some_and(|body| {
            matches!(
                management::Message::decode(body),
                Err(management::Error::InvalidJson)
            )
        });
    checks.push(check("management-malformed", "InvalidJson", malformed));
    let mut d = management::FrameDecoder::new();
    let truncated = d.feed(&[0, 0, 0, 4, b'{']) == Ok(5) && d.frame().is_none();
    checks.push(check("management-truncated", "incomplete frame", truncated));
    let mut d = management::FrameDecoder::new();
    let mut oversized = Vec::from(((management::MAX_FRAME + 1) as u32).to_be_bytes());
    oversized.extend_from_slice(&[0; 16]);
    let oversized = d.feed(&oversized) == Err(management::Error::Oversized)
        && d.frame().is_none()
        && std::mem::size_of::<management::FrameDecoder>() <= management::MAX_FRAME + 64;
    checks.push(check(
        "management-oversized",
        "Oversized before body buffering",
        oversized,
    ));
    checks
}

// This entrypoint runs only in a dedicated subprocess, never in the runner.
#[cfg(target_os = "linux")]
pub fn memory_child() -> i32 {
    unsafe {
        // Drop root identity before exercising mlock. For non-root, clear any
        // capabilities inherited through the executable or ambient set.
        if libc::geteuid() == 0
            && (libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(65534) != 0
                || libc::setuid(65534) != 0)
        {
            return 2;
        }
        #[repr(C)]
        struct Header {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        struct Data {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        let mut header = Header {
            version: 0x20080522,
            pid: 0,
        };
        let data = [
            Data {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            Data {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        if libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) != 0 {
            return 2;
        }
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) != 0 {
            return 2;
        }
        let mut actual = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut actual) != 0
            || actual.rlim_cur != 0
            || actual.rlim_max != 0
        {
            return 2;
        }
    }
    match pico2_kes_agent::memory::SecretBuffer::new(32) {
        Err(e) if matches!(e.raw_os_error(), Some(libc::EPERM | libc::ENOMEM)) => {
            println!("lock-denied-not-ready");
            0
        }
        Err(_) => 2,
        Ok(_) => 1,
    }
}
#[cfg(not(target_os = "linux"))]
pub fn memory_child() -> i32 {
    2
}

fn memory_check() -> Check {
    let mut result = Check {
        name: "memory-lock-denial",
        expected: "OS lock denied; no ready state or sensitive output",
        observed: "unavailable",
        executions: 0,
        passed: false,
    };
    let exe = match std::env::current_exe() {
        Ok(x) => x,
        Err(_) => return result,
    };
    let mut child = match Command::new(exe)
        .arg("__foundation-memory-child")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(x) => x,
        Err(_) => return result,
    };
    result.executions = 1;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let read = |mut stream: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut b = Vec::new();
            let _ = stream.by_ref().take(4097).read_to_end(&mut b);
            b
        })
    };
    let out = read(Box::new(stdout));
    let err = read(Box::new(stderr));
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let out = out.join().unwrap_or_default();
    let err = err.join().unwrap_or_default();
    if let Some(status) = status {
        if status.success() && out == b"lock-denied-not-ready\n" && err.is_empty() {
            result.passed = true;
            result.observed = "lock denied; not ready; no sensitive output";
        } else if status.code() != Some(2) || !out.is_empty() || !err.is_empty() {
            result.observed = "unexpected child outcome or output";
        }
    }
    result
}

fn fixture_checks() -> Vec<Check> {
    let oversized = vec![b' '; fixture::MAX_FIXTURE_BYTES + 1];
    let cases: [(&str, &[u8]); 4] = [
        ("fixture-empty", b"{}"),
        ("fixture-malformed", b"{not json}"),
        ("fixture-trailing", b"{} {}"),
        ("fixture-oversized", &oversized),
    ];
    cases.into_iter().map(|(name, bytes)| {
        let mut side_effect = false;
        if fixture::parse_fixture(bytes).is_ok() { side_effect = true; }
        check(name, "rejected before side effect", !side_effect)
    }).chain(std::iter::once({
        let digest = "a".repeat(64);
        let pinned = serde_json::json!({"path": "/disposable/file", "sha256": digest});
        let pools: Vec<_> = (0..64).map(|i| serde_json::json!({
            "public_identity": format!("pool-{i}"),
            "cold_key_path": "/disposable/cold",
            "vrf_key_path": "/disposable/vrf"
        })).collect();
        let mut document = serde_json::json!({
            "candidate_sha256": digest, "source_sha256": digest,
            "device_pin": "disposable-device", "fitted_part_record": "/disposable/part",
            "firmware": pinned, "daemon": pinned, "cli": pinned, "decoder": pinned, "peer": pinned,
            "pools": pools,
            "network": {"name": "testnet", "isolated": true, "disposable_credentials": true,
                "genesis": "/disposable/genesis", "node_socket": "/disposable/socket"},
            "recipient_host": "test-host",
            "evidence_directory": "/disposable/evidence"
        });
        let valid = serde_json::to_vec(&document).unwrap();
        let valid_accepted = fixture::parse_fixture(&valid).is_ok();
        document["network"]["isolated"] = serde_json::json!(false);
        let invalid = serde_json::to_vec(&document).unwrap();
        let mut side_effect = false;
        if fixture::parse_fixture(&invalid).is_ok() { side_effect = true; }
        check("fixture-production-network", "valid control accepted; production rejected before side effect", valid_accepted && !side_effect)
    })).collect()
}

pub fn run() -> i32 {
    let deadline = Instant::now() + Duration::from_secs(30 * 60);
    let mut checks = codec_checks();
    checks.push(memory_check());
    checks.extend(fixture_checks());
    checks.extend(host_checks(deadline));
    match evidence::run(&checks) {
        Ok((verdict, path)) => {
            println!(
                "{}",
                serde_json::json!({"verdict": match verdict { Verdict::Pass => "pass-for-foundation-scope", Verdict::Fail => "failed", Verdict::Inconclusive => "inconclusive" }, "report": path.to_string_lossy()})
            );
            if matches!(verdict, Verdict::Pass) {
                0
            } else {
                1
            }
        }
        Err(_) => {
            eprintln!("foundation evidence unavailable");
            println!("{{\"verdict\":\"inconclusive\",\"report\":null}}");
            1
        }
    }
}

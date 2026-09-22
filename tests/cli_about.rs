use std::process::Command;

#[test]
fn about_is_informational_and_version_remains_machine_readable() {
    for executable in [
        env!("CARGO_BIN_EXE_hangang"),
        env!("CARGO_BIN_EXE_hangang-dsr"),
        env!("CARGO_BIN_EXE_hangang-acme-issuer"),
        env!("CARGO_BIN_EXE_hangang-admin-gateway"),
        env!("CARGO_BIN_EXE_hangang-auth-bridge"),
        env!("CARGO_BIN_EXE_hangang-network-bridge"),
        env!("CARGO_BIN_EXE_hangang-release-sign"),
    ] {
        let output = Command::new(executable)
            .arg("--about")
            .env(
                "HANGANG_UPDATE_KEY",
                "invalid-key-must-not-be-loaded-by-about",
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{executable}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("https://github.com/ziozzang/hangang"));
        assert!(text.contains("Jioh Jung <jung@jioh.net>"));
        assert!(text.contains(env!("CARGO_PKG_VERSION")));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_hangang"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        format!("hangang {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn github_installation_requires_explicit_supervision_and_trust() {
    for args in [
        vec!["--update-github"],
        vec!["--supervised", "--update-github"],
        vec![
            "--supervised",
            "--update-github",
            "--update-key",
            "test",
            "--update-manifest",
            "https://example.invalid/manifest",
        ],
        vec![
            "--supervised",
            "--update-github",
            "--update-key",
            "test",
            "--update-ca",
            "ca.pem",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_hangang"))
            .args(args)
            .env_remove("HANGANG_UPDATE_KEY")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn supervised_mode_is_rejected_outside_linux() {
    let output = Command::new(env!("CARGO_BIN_EXE_hangang"))
        .arg("--supervised")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--supervised is supported only on Linux")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_does_not_offer_a_lua_sandbox_bypass() {
    let output = Command::new(env!("CARGO_BIN_EXE_hangang"))
        .arg("--allow-unsandboxed-lua")
        .env_remove("HANGANG_UPDATE_KEY")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_lua_requires_explicit_development_opt_in() {
    for allow in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hangang"));
        command.arg("--lua-worker");
        if allow {
            command.arg("--allow-unsandboxed-lua");
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.success(), allow);
        if !allow {
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("Lua syscall isolation requires Linux")
            );
        }
    }
}

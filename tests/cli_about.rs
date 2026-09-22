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

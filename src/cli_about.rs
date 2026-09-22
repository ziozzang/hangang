//! Informational CLI output that does not load configuration or credentials.
pub const FOOTER: &str =
    "Source: https://github.com/ziozzang/hangang\nAuthor: Jioh Jung <jung@jioh.net>";

pub fn print_if_requested(binary: &str) -> bool {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--about")) || args.next().is_some() {
        return false;
    }
    println!("{binary} {}\n{FOOTER}", env!("CARGO_PKG_VERSION"));
    true
}

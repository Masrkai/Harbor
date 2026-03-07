use crate::utils::logger::*;
use nix::unistd::geteuid;

pub fn check_root() {
    let mut logger = Logger::new();

    if !geteuid().is_root() {
        logger.info_fmt(format_args!(
            "This tool requires root privileges for raw socket access, Try running with sudo!"
        ));
        std::process::exit(1);
    } else {
        logger.info_fmt(format_args!(
            "Root privilages have been granted suceessfully"
        ));
    }
}

// Backup for decision later
// pub fn is_root() -> bool {
//     std::process::Command::new("id")
//         .arg("-u")
//         .output()
//         .map(|o| o.stdout.starts_with(b"0"))
//         .unwrap_or(false)
// }

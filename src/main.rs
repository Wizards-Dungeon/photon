#![feature(panic_info_message)]
use std::io;

#[macro_use]
extern crate obfstr;

mod imp;

fn main() -> io::Result<()> {
    std::panic::set_hook(Box::new(|panic_info| {
        if let Some(&m) = panic_info.message() {
            eprintln!("[ERROR] {}", ::std::fmt::format(m));
        } else {
            eprintln!("[ERROR] Internal error");
        }
        _ = imp::pause();
        std::process::exit(1);
    }));

    let client = imp::WindowsActivatorClient::new();
    client.install_pk().unwrap();
    client.create_ticket().unwrap();
    client.install_ticket().unwrap();
    _ = imp::pause();

    Ok(())
}

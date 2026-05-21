#![windows_subsystem = "windows"]

mod gui;

pub use rust_string_encryptor::{decrypt_text, encrypt_text};

fn main() {
    gui::run_gui().expect("Failed to launch GUI");
}
// Hide the console only in release builds so debug runs still show panics.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod gui;

use rust_string_encryptor::{decrypt_text, encrypt_text};

fn main() {
    gui::run_gui().expect("Failed to launch GUI");
}

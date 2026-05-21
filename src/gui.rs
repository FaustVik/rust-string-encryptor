use eframe::egui;
use zeroize::Zeroize;
use crate::{encrypt_text, decrypt_text};

pub struct EncryptorApp {
    encrypt_input: String,
    encrypt_password: String,
    encrypt_output: String,
    encrypt_error: String,
    decrypt_input: String,
    decrypt_password: String,
    decrypt_output: String,
    decrypt_error: String,
}

impl Default for EncryptorApp {
    fn default() -> Self {
        Self {
            encrypt_input: String::new(),
            encrypt_password: String::new(),
            encrypt_output: String::new(),
            encrypt_error: String::new(),
            decrypt_input: String::new(),
            decrypt_password: String::new(),
            decrypt_output: String::new(),
            decrypt_error: String::new(),
        }
    }
}

impl Drop for EncryptorApp {
    fn drop(&mut self) {
        self.encrypt_password.zeroize();
        self.decrypt_password.zeroize();
        self.encrypt_input.zeroize();
        self.decrypt_output.zeroize();
    }
}

impl EncryptorApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self::default()
    }

    fn encrypt_section(&mut self, ui: &mut egui::Ui) {
        ui.heading("🔒 Encrypt");
        ui.add_space(10.0);

        ui.label("Plaintext:");
        ui.add(
            egui::TextEdit::multiline(&mut self.encrypt_input)
                .desired_width(f32::INFINITY)
                .desired_rows(5)
                .hint_text("Enter text to encrypt...")
        );
        ui.add_space(5.0);

        ui.label("Password:");
        ui.add(
            egui::TextEdit::singleline(&mut self.encrypt_password)
                .password(true)
                .desired_width(f32::INFINITY)
                .hint_text("Enter password...")
        );
        ui.add_space(10.0);

        if ui.button("🔐 Encrypt").clicked() {
            self.encrypt_error.clear();
            self.encrypt_output.clear();

            if self.encrypt_input.is_empty() {
                self.encrypt_error = "Please enter text to encrypt".to_string();
            } else if self.encrypt_password.is_empty() {
                self.encrypt_error = "Please enter a password".to_string();
            } else {
                match encrypt_text(&self.encrypt_password, self.encrypt_input.as_bytes()) {
                    Ok(encrypted) => {
                        self.encrypt_output = encrypted;
                    }
                    Err(e) => {
                        self.encrypt_error = format!("Encryption failed: {}", e);
                    }
                }
            }
        }

        ui.add_space(10.0);

        if !self.encrypt_error.is_empty() {
            ui.colored_label(egui::Color32::from_rgb(255, 100, 100), &self.encrypt_error);
        }

        if !self.encrypt_output.is_empty() {
            ui.label("Encrypted output:");
            ui.add(
                egui::TextEdit::multiline(&mut self.encrypt_output)
                    .desired_width(f32::INFINITY)
                    .desired_rows(5)
                    .interactive(false)
            );
            ui.add_space(5.0);
            if ui.button("📋 Copy to Clipboard").clicked() {
                ui.ctx().copy_text(self.encrypt_output.clone());
            }
        }
    }

    fn decrypt_section(&mut self, ui: &mut egui::Ui) {
        ui.heading("🔓 Decrypt");
        ui.add_space(10.0);

        ui.label("Encrypted text:");
        ui.add(
            egui::TextEdit::multiline(&mut self.decrypt_input)
                .desired_width(f32::INFINITY)
                .desired_rows(5)
                .hint_text("Paste encrypted text here...")
        );
        ui.add_space(5.0);

        ui.label("Password:");
        ui.add(
            egui::TextEdit::singleline(&mut self.decrypt_password)
                .password(true)
                .desired_width(f32::INFINITY)
                .hint_text("Enter password...")
        );
        ui.add_space(10.0);

        if ui.button("🔓 Decrypt").clicked() {
            self.decrypt_error.clear();
            self.decrypt_output.clear();

            if self.decrypt_input.is_empty() {
                self.decrypt_error = "Please enter encrypted text".to_string();
            } else if self.decrypt_password.is_empty() {
                self.decrypt_error = "Please enter a password".to_string();
            } else {
                match decrypt_text(&self.decrypt_password, &self.decrypt_input) {
                    Ok(decrypted) => {
                        match String::from_utf8(decrypted) {
                            Ok(text) => {
                                self.decrypt_output = text;
                            }
                            Err(_) => {
                                self.decrypt_error = "Decrypted data is not valid UTF-8".to_string();
                            }
                        }
                    }
                    Err(e) => {
                        self.decrypt_error = format!("Decryption failed: {}", e);
                    }
                }
            }
        }

        ui.add_space(10.0);

        if !self.decrypt_error.is_empty() {
            ui.colored_label(egui::Color32::from_rgb(255, 100, 100), &self.decrypt_error);
        }

        if !self.decrypt_output.is_empty() {
            ui.label("Decrypted output:");
            ui.add(
                egui::TextEdit::multiline(&mut self.decrypt_output)
                    .desired_width(f32::INFINITY)
                    .desired_rows(5)
                    .interactive(false)
            );
            ui.add_space(5.0);
            if ui.button("📋 Copy to Clipboard").clicked() {
                ui.ctx().copy_text(self.decrypt_output.clone());
            }
        }
    }
}

impl eframe::App for EncryptorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Set dark theme
        ctx.set_visuals(egui::Visuals::dark());

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🔐 Rust String Encryptor");
            ui.add_space(20.0);

            ui.columns(2, |columns| {
                // Left column - Encrypt
                columns[0].group(|ui| {
                    self.encrypt_section(ui);
                });

                // Right column - Decrypt
                columns[1].group(|ui| {
                    self.decrypt_section(ui);
                });
            });
        });
    }
}

pub fn run_gui() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 600.0])
            .with_min_inner_size([800.0, 500.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Rust String Encryptor",
        options,
        Box::new(|cc| Ok(Box::new(EncryptorApp::new(cc)))),
    )
}

use crate::{decrypt_text, encrypt_text};
use eframe::egui;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

/// Copied plaintext is wiped from the clipboard after this delay.
const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);
/// Passwords shorter than this get a (non-blocking) warning.
const MIN_RECOMMENDED_PASSWORD_LEN: usize = 12;

const ERROR_COLOR: egui::Color32 = egui::Color32::from_rgb(255, 100, 100);
const WARN_COLOR: egui::Color32 = egui::Color32::from_rgb(230, 190, 80);

type Job<T> = Receiver<anyhow::Result<T>>;

/// Runs `f` on a worker thread so Argon2 doesn't freeze the UI, and repaints
/// once the result is ready.
fn spawn_job<T, F>(ctx: &egui::Context, f: F) -> Job<T>
where
    T: Send + 'static,
    F: FnOnce() -> anyhow::Result<T> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    let ctx = ctx.clone();
    std::thread::spawn(move || {
        let _ = tx.send(f());
        ctx.request_repaint();
    });
    rx
}

/// Returns the job result once it's finished; `None` while it is still running.
fn poll_job<T>(job: &mut Option<Job<T>>) -> Option<anyhow::Result<T>> {
    let result = match job.as_ref()?.try_recv() {
        Ok(result) => result,
        Err(TryRecvError::Empty) => return None,
        Err(TryRecvError::Disconnected) => Err(anyhow::anyhow!("worker thread crashed")),
    };
    *job = None;
    Some(result)
}

#[derive(Default)]
pub struct EncryptorApp {
    encrypt_input: String,
    encrypt_password: String,
    encrypt_password_confirm: String,
    encrypt_output: String,
    encrypt_error: String,
    encrypt_job: Option<Job<String>>,
    decrypt_input: String,
    decrypt_password: String,
    decrypt_output: String,
    decrypt_error: String,
    decrypt_job: Option<Job<Zeroizing<String>>>,
    clipboard_clear_at: Option<Instant>,
}

impl Drop for EncryptorApp {
    fn drop(&mut self) {
        self.encrypt_password.zeroize();
        self.encrypt_password_confirm.zeroize();
        self.decrypt_password.zeroize();
        self.encrypt_input.zeroize();
        self.decrypt_output.zeroize();
        // egui can no longer flush clipboard commands at this point, so wipe
        // pending plaintext from the clipboard directly.
        if self.clipboard_clear_at.is_some() {
            if let Ok(mut clipboard) = arboard::Clipboard::new() {
                let _ = clipboard.clear();
            }
        }
    }
}

impl EncryptorApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        Self::default()
    }

    fn poll_jobs(&mut self) {
        if let Some(result) = poll_job(&mut self.encrypt_job) {
            match result {
                Ok(encrypted) => self.encrypt_output = encrypted,
                Err(e) => self.encrypt_error = format!("Encryption failed: {}", e),
            }
        }
        if let Some(result) = poll_job(&mut self.decrypt_job) {
            match result {
                Ok(text) => self.decrypt_output.push_str(&text),
                Err(e) => self.decrypt_error = format!("Decryption failed: {}", e),
            }
        }
    }

    fn handle_clipboard_timer(&mut self, ctx: &egui::Context) {
        let Some(deadline) = self.clipboard_clear_at else {
            return;
        };
        let now = Instant::now();
        if now >= deadline {
            ctx.copy_text(String::new());
            self.clipboard_clear_at = None;
        } else {
            // Tick once a second to keep the countdown label current.
            ctx.request_repaint_after((deadline - now).min(Duration::from_secs(1)));
        }
    }

    fn start_encrypt(&mut self, ctx: &egui::Context) {
        self.encrypt_error.clear();
        self.encrypt_output.clear();

        if self.encrypt_input.is_empty() {
            self.encrypt_error = "Please enter text to encrypt".to_string();
        } else if self.encrypt_password.is_empty() {
            self.encrypt_error = "Please enter a password".to_string();
        } else if self.encrypt_password != self.encrypt_password_confirm {
            self.encrypt_error = "Passwords do not match".to_string();
        } else {
            let password = Zeroizing::new(self.encrypt_password.clone());
            let input = Zeroizing::new(self.encrypt_input.clone());
            self.encrypt_job = Some(spawn_job(ctx, move || {
                encrypt_text(&password, input.as_bytes())
            }));
        }
    }

    fn start_decrypt(&mut self, ctx: &egui::Context) {
        self.decrypt_error.clear();
        self.decrypt_output.zeroize();

        if self.decrypt_input.is_empty() {
            self.decrypt_error = "Please enter encrypted text".to_string();
        } else if self.decrypt_password.is_empty() {
            self.decrypt_error = "Please enter a password".to_string();
        } else {
            let password = Zeroizing::new(self.decrypt_password.clone());
            let input = self.decrypt_input.clone();
            self.decrypt_job = Some(spawn_job(ctx, move || {
                // `decrypted` is Zeroizing, so the raw bytes are wiped on
                // drop even when they turn out not to be valid UTF-8.
                let decrypted = decrypt_text(&password, &input)?;
                let text = std::str::from_utf8(&decrypted)
                    .map_err(|_| anyhow::anyhow!("decrypted data is not valid UTF-8"))?;
                Ok(Zeroizing::new(text.to_owned()))
            }));
        }
    }

    fn encrypt_section(&mut self, ui: &mut egui::Ui) {
        let busy = self.encrypt_job.is_some();

        ui.heading("🔒 Encrypt");
        ui.add_space(10.0);

        ui.label("Plaintext:");
        ui.add(
            egui::TextEdit::multiline(&mut self.encrypt_input)
                .desired_width(f32::INFINITY)
                .desired_rows(5)
                .hint_text("Enter text to encrypt..."),
        );
        ui.add_space(5.0);

        ui.label("Password:");
        ui.add(
            egui::TextEdit::singleline(&mut self.encrypt_password)
                .password(true)
                .desired_width(f32::INFINITY)
                .hint_text("Enter password..."),
        );
        ui.add_space(5.0);

        ui.label("Confirm password:");
        ui.add(
            egui::TextEdit::singleline(&mut self.encrypt_password_confirm)
                .password(true)
                .desired_width(f32::INFINITY)
                .hint_text("Repeat password..."),
        );

        let password_len = self.encrypt_password.chars().count();
        if password_len > 0 && password_len < MIN_RECOMMENDED_PASSWORD_LEN {
            ui.colored_label(
                WARN_COLOR,
                format!(
                    "Weak password: {} characters or more is recommended",
                    MIN_RECOMMENDED_PASSWORD_LEN
                ),
            );
        }
        ui.add_space(10.0);

        ui.horizontal(|ui| {
            if ui
                .add_enabled(!busy, egui::Button::new("🔐 Encrypt"))
                .clicked()
            {
                self.start_encrypt(ui.ctx());
            }
            if busy {
                ui.spinner();
                ui.label("Deriving key...");
            }
        });

        ui.add_space(10.0);

        if !self.encrypt_error.is_empty() {
            ui.colored_label(ERROR_COLOR, &self.encrypt_error);
        }

        if !self.encrypt_output.is_empty() {
            ui.label("Encrypted output:");
            ui.add(
                egui::TextEdit::multiline(&mut self.encrypt_output)
                    .desired_width(f32::INFINITY)
                    .desired_rows(5)
                    .interactive(false),
            );
            ui.add_space(5.0);
            if ui.button("📋 Copy to Clipboard").clicked() {
                ui.ctx().copy_text(self.encrypt_output.clone());
                // Ciphertext is safe to keep; don't wipe it later.
                self.clipboard_clear_at = None;
            }
        }
    }

    fn decrypt_section(&mut self, ui: &mut egui::Ui) {
        let busy = self.decrypt_job.is_some();

        ui.heading("🔓 Decrypt");
        ui.add_space(10.0);

        ui.label("Encrypted text:");
        ui.add(
            egui::TextEdit::multiline(&mut self.decrypt_input)
                .desired_width(f32::INFINITY)
                .desired_rows(5)
                .hint_text("Paste encrypted text here..."),
        );
        ui.add_space(5.0);

        ui.label("Password:");
        ui.add(
            egui::TextEdit::singleline(&mut self.decrypt_password)
                .password(true)
                .desired_width(f32::INFINITY)
                .hint_text("Enter password..."),
        );
        ui.add_space(10.0);

        ui.horizontal(|ui| {
            if ui
                .add_enabled(!busy, egui::Button::new("🔓 Decrypt"))
                .clicked()
            {
                self.start_decrypt(ui.ctx());
            }
            if busy {
                ui.spinner();
                ui.label("Deriving key...");
            }
        });

        ui.add_space(10.0);

        if !self.decrypt_error.is_empty() {
            ui.colored_label(ERROR_COLOR, &self.decrypt_error);
        }

        if !self.decrypt_output.is_empty() {
            ui.label("Decrypted output:");
            ui.add(
                egui::TextEdit::multiline(&mut self.decrypt_output)
                    .desired_width(f32::INFINITY)
                    .desired_rows(5)
                    .interactive(false),
            );
            ui.add_space(5.0);
            ui.horizontal(|ui| {
                if ui.button("📋 Copy to Clipboard").clicked() {
                    ui.ctx().copy_text(self.decrypt_output.clone());
                    self.clipboard_clear_at = Some(Instant::now() + CLIPBOARD_CLEAR_AFTER);
                }
                if let Some(deadline) = self.clipboard_clear_at {
                    let secs = deadline
                        .saturating_duration_since(Instant::now())
                        .as_secs_f32()
                        .ceil();
                    ui.label(format!("Clipboard will be cleared in {} s", secs));
                }
            });
        }
    }
}

impl eframe::App for EncryptorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_jobs();
        self.handle_clipboard_timer(ctx);

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
            .with_inner_size([1000.0, 650.0])
            .with_min_inner_size([800.0, 550.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Rust String Encryptor",
        options,
        Box::new(|cc| Ok(Box::new(EncryptorApp::new(cc)))),
    )
}

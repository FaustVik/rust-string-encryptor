mod gui;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rpassword::read_password;
use rust_string_encryptor::{encrypt_text, decrypt_text};
use std::io::{Read, Write};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(author, version, about = "Encrypt/decrypt short secrets using password (AES-256-GCM + Argon2id)")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Launch GUI application
    Gui,
    /// Encrypt a string (reads from stdin if no --text provided)
    Encrypt {
        /// text to encrypt (optional). If omitted, read from stdin.
        #[arg(short, long)]
        text: Option<String>,
    },
    /// Decrypt a block (reads armored block from stdin if no --text provided)
    Decrypt {
        /// armored block (optional). If omitted, read from stdin.
        #[arg(short, long)]
        text: Option<String>,
    },
}

fn read_stdin_to_string() -> Result<String> {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).context("read stdin")?;
    Ok(s)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Gui => {
            gui::run_gui().map_err(|e| anyhow::anyhow!("GUI error: {}", e))?;
            Ok(())
        }
        Commands::Encrypt { text } => {
            let input = match text {
                Some(t) => t,
                None => read_stdin_to_string()?,
            };
            // trim trailing newline if pasted
            let input = input.trim_end_matches('\n');
            eprint!("Enter passphrase: ");
            let pass = read_password()?;
            let armored = encrypt_text(&pass, input.as_bytes())?;
            // ensure pass doesn't linger
            let mut p = pass;
            p.zeroize();

            println!("{}", armored);
            Ok(())
        }
        Commands::Decrypt { text } => {
            let input = match text {
                Some(t) => t,
                None => read_stdin_to_string()?,
            };
            eprint!("Enter passphrase: ");
            let pass = read_password()?;
            let plaintext = decrypt_text(&pass, &input)?;
            let mut p = pass;
            p.zeroize();

            // print raw plaintext to stdout
            std::io::stdout().write_all(&plaintext)?;
            std::io::stdout().write_all(b"\n")?;
            Ok(())
        }
    }
}
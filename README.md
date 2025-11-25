# rust-string-encryptor

Утилита для шифрования/дешифрования коротких секретов (строк). Использует AES-256-GCM и Argon2id.

## Локальная сборка

Сборка на каждой целевой ОС (рекомендуется):

```bash
# на Linux/macOS
cargo build --release
# бинарник в target/release/rust-string-encryptor

# на Windows (PowerShell)
cargo build --release
# бинарник: target\release\rust-string-encryptor.exe


# Кросс-компиляция к Windows с Linux

rustup target add x86_64-pc-windows-gnu
# на Debian/Ubuntu:
sudo apt install mingw-w64
# затем
cargo build --release --target x86_64-pc-windows-gnu
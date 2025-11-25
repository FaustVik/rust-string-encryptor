# Rust String Encryptor

Простая кросс-платформенная утилита для шифрования и дешифрования текстовых данных с использованием пароля.

## Технические детали

- **Шифрование**: AES-256-GCM (аутентифицированное шифрование)
- **Деривация ключа**: Argon2id (защита от брутфорса)
- **Формат вывода**: Base64 с заголовками (легко копировать/вставлять)

## Установка

### Из исходников

```bash
cargo build --release
```

Исполняемый файл будет находиться в `target/release/rust-string-encryptor` (или `.exe` на Windows).

## Использование

### Шифрование текста

```bash
# С параметром --text
rust-string-encryptor encrypt --text "мой секретный текст"

# Или из stdin
echo "мой секретный текст" | rust-string-encryptor encrypt
```

Программа запросит пароль и выведет зашифрованный блок:

```
-----BEGIN RUST-ENC V1-----
base64encodeddata...
-----END RUST-ENC V1-----
```

### Дешифрование текста

```bash
# С параметром --text (вставьте весь блок в кавычках)
rust-string-encryptor decrypt --text "-----BEGIN RUST-ENC V1-----
...
-----END RUST-ENC V1-----"

# Или из stdin
cat encrypted.txt | rust-string-encryptor decrypt
```

Программа запросит пароль и выведет расшифрованный текст.

## Примеры

### Шифрование и сохранение в файл

```bash
rust-string-encryptor encrypt --text "секретное сообщение" > encrypted.txt
```

### Дешифрование из файла

```bash
rust-string-encryptor decrypt < encrypted.txt
```

### Цепочка команд

```bash
echo "тест" | rust-string-encryptor encrypt | rust-string-encryptor decrypt
```

## Кросс-компиляция

### Для Linux (из Windows)

Требуется установить линкер. Рекомендуется компилировать на целевой платформе:

```bash
# На Linux
cargo build --release --target x86_64-unknown-linux-gnu
```

### Для Windows

```bash
cargo build --release --target x86_64-pc-windows-msvc
```

### Для macOS

```bash
cargo build --release --target x86_64-apple-darwin
# или для Apple Silicon
cargo build --release --target aarch64-apple-darwin
```

## Безопасность

- Пароли не сохраняются в памяти после использования (zeroize)
- Используется криптографически стойкий генератор случайных чисел (OsRng)
- Каждое шифрование использует уникальную соль и nonce
- Argon2id защищает от атак по словарю и GPU-ускоренного брутфорса

## Лицензия

MIT
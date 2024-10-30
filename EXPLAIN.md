
# Jock - Detailed Code Explanation

`Jock` is a Rust-based encryption tool designed for file encryption and decryption via password hashing. This README will walk through each part of the code, explaining its purpose, structure, and flow.

## Table of Contents
1. [Project Structure](#project-structure)
2. [Code Breakdown](#code-breakdown)
   - [Imports](#imports)
   - [Custom Error Type](#custom-error-type)
   - [Main Function](#main-function)
   - [Helper Functions](#helper-functions)
   - [Encryption and Decryption Functions](#encryption-and-decryption-functions)
   - [File Processing Functions](#file-processing-functions)
   - [Interactive CLI Mode](#interactive-cli-mode)

## Project Structure
- **JockError**: Custom error type for handling various errors, such as file I/O issues or invalid paths.
- **Main function**: Parses and executes commands (`lock`, `open`, `cli`).
- **Helper functions**: Additional functions like `hash_password` for hashing the password, `encrypt`, and `decrypt`.
- **File processing functions**: For encryption and decryption of files.
- **CLI mode**: An interactive mode for manual encryption/decryption of messages.

## Code Breakdown

### Imports
The code imports the following modules and dependencies:
```rust
use std::{
    env::args,
    fs::{self, File},
    io::{self, stdin, stdout, BufWriter, Write},
    path::{Path, PathBuf},
};
use indicatif::{ProgressBar, ProgressStyle};
```
- `std::env::args`: For parsing command-line arguments.
- `std::fs`: Provides file handling functions.
- `std::io`: Includes I/O handling modules like `stdin`, `stdout`, `BufWriter`.
- `std::path`: Path handling utilities.
- `indicatif`: External crate for creating and styling progress bars.

### Custom Error Type
```rust
#[derive(Debug)]
pub enum JockError {
    Io(io::Error),
    PathNotFound(PathBuf),
    InvalidFormat,
    EncryptionNotAllowedForFolder,
}
```
- `JockError`: A custom error type to handle different errors that can arise during file I/O, path validation, and unsupported operations.
- Variants:
  - `Io`: Wraps standard I/O errors.
  - `PathNotFound`: Path not found error, useful for cases where the specified path is missing.
  - `InvalidFormat`: Error if the format of an encrypted file is incorrect.
  - `EncryptionNotAllowedForFolder`: Disallows encryption of directories.

### Main Function
The `main` function processes command-line arguments and routes commands:
```rust
fn main() {
    let args: Vec<String> = args().collect();

    if args.len() < 2 || args[1].eq_ignore_ascii_case("--help") || args[1].eq_ignore_ascii_case("-h") {
        print_help();
        return;
    }

    let command = &args[1];
    if command == "cli" {
        climode();
        return;
    }

    let password = &args[2];
    let file_path = Path::new(&args[3]);
    let hashed_password = hash_password(password.as_bytes());

    if file_path.is_dir() {
        eprintln!("Error: Folder encryption is currently not supported. Please specify a file.");
        return;
    }

    match command.as_str() {
        "lock" => {
            let output_file = format!("{}.jock", file_path.file_stem().unwrap().to_string_lossy());
            println!("Encrypting file: {}", file_path.display());
            if let Err(e) = encrypt_file(file_path, &hashed_password, &output_file) {
                eprintln!("Error encrypting file: {:?}", e);
            } else {
                println!("File encrypted successfully. Output file: {}", output_file);
            }
        }
        "open" => {
            println!("Decrypting file: {}", file_path.display());
            if let Err(e) = decrypt_file(file_path, &hashed_password) {
                eprintln!("Error decrypting file: {:?}", e);
            }
        }
        _ => eprintln!("Invalid command. Use 'lock' to encrypt or 'open' to decrypt.
You gave me: {}", command),
    }
}
```
1. **Argument Parsing**: Collects command-line arguments.
2. **Help Option**: Prints help if arguments are missing or `--help/-h` flags are provided.
3. **CLI Mode**: Launches interactive CLI if `cli` command is given.
4. **Password and Path Handling**: Retrieves password and file path, then hashes the password.
5. **Folder Check**: Prevents directory encryption with a message.
6. **Command Execution**:
   - **Lock**: Encrypts the file, outputs `.jock` file, and deletes the original.
   - **Open**: Decrypts the file and outputs it with the correct extension.

### Helper Functions

#### `print_help`
Displays usage and command examples.
```rust
fn print_help() { ... }
```

#### `hash_password`
Hashes the password by iterating over each byte, performing a basic operation.
```rust
fn hash_password(password: &[u8]) -> Vec<u8> { ... }
```

### Encryption and Decryption Functions

#### `encrypt`
Encrypts data by adding hashed password bytes to each byte in the data.
```rust
fn encrypt(data: &[u8], hashed_password: &[u8]) -> Vec<u8> { ... }
```

#### `decrypt`
Decrypts data by subtracting hashed password bytes from each byte in the data.
```rust
fn decrypt(data: &[u8], hashed_password: &[u8]) -> Vec<u8> { ... }
```

### File Processing Functions

#### `encrypt_file`
Encrypts a file in chunks and writes to an output file with a progress bar.
```rust
fn encrypt_file(path: &Path, hashed_password: &[u8], output_file: &str) -> Result<(), JockError> { ... }
```
1. **Reads File**: Reads data and encrypts it.
2. **Writes Encrypted Data**: Uses `BufWriter` to write in chunks.
3. **Progress Bar**: Updates progress in chunks.
4. **File Extension Handling**: Stores the original extension for future decryption.
5. **Delete Original File**: Deletes original upon successful encryption.

#### `decrypt_file`
Decrypts an encrypted file in chunks and writes to a new output file.
```rust
fn decrypt_file(encrypted_file: &Path, hashed_password: &[u8]) -> Result<(), JockError> { ... }
```
1. **Reads Encrypted File**: Reads the data and extracts the file extension.
2. **Decrypts Data**: Decrypts the data, ignoring the extension bytes.
3. **Writes Decrypted Data**: Outputs a new file with original extension and shows a progress bar.
4. **Delete Encrypted File**: Removes the encrypted file after successful decryption.

### Interactive CLI Mode

The `climode` function launches an interactive interface for encrypting and decrypting messages manually.
```rust
fn climode() { ... }
```
1. **Loop for Actions**: Allows the user to choose options (encrypt, decrypt, exit).
2. **Encrypt Message**: Reads message and password, then prints encrypted output.
3. **Decrypt Message**: Accepts encrypted input, decrypts, and displays the message.

---
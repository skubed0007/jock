
# Jock Encryption Tool

## Overview

**Jock** is a simple command-line encryption and decryption tool written in Rust. It allows users to securely lock (encrypt) and open (decrypt) files, folders, or messages using a password. The tool provides an interactive command-line interface for quick encryption/decryption of messages and supports both file and folder operations.

## Features

- **Encrypt and Decrypt**: Securely encrypt files or folders using a password.
- **Interactive CLI**: An interactive mode for quickly encrypting or decrypting messages.
- **Progress Indication**: Provides a visual spinner to indicate progress during operations.
- **Custom Output**: Option to specify custom output filenames for encrypted files.

## Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/skubed0007/jock
   cd jock
   ```

2. **Build the project**:

   Make sure you have Rust and Cargo installed. Then, run:

   ```bash
   cargo build --release
   ```

3. **Run the tool**:

   After building, you can run the executable:

   ```bash
   ./target/release/jock <command> <args>
   ```

# OR

**Download binary file from release section**
## Usage

### Commands

- **lock**: Encrypts the specified files, folders, or messages.
- **open**: Decrypts the specified files or folders.
- **cli**: Encrypts or decrypts messages interactively.

### Arguments

- `<password>`: A password to secure the encryption or decryption process.
- `<file_or_folder_or_message>`: The paths of files or folders to encrypt or decrypt, or messages to encrypt.
- `--output <output_file>`: Specify a custom output file path. If not provided, the original files will be saved with a `.jock` extension.

### Examples
> Giving ``--output file_name`` is not needed

1. **Encrypt Files**:

   ```bash
   jock lock mypassword /path/to/file1 /path/to/file2 --output /path/to/encrypted_file
   ```

2. **Decrypt Files**:

   ```bash
   jock open mypassword /path/to/encrypted_file.jock --output /path/to/decrypted_file
   ```

3. **Interactive CLI**:

   ```bash
   jock cli
   ```

> #### YOU CAN ALSO LOCK FOLDERS BY PASSING IN FOLDERS INSTEAD OF FILES!

## License

This project is licensed under the **GNU General Public License v3.0** (GPL-3.0) and the **Creative Commons Attribution 4.0 International License** (CC BY 4.0).

### GNU General Public License v3.0 (GPL-3.0)

The GPL-3.0 license allows users to freely use, modify, and distribute the software, provided that any derivative works are also licensed under the GPL-3.0. This ensures that the software remains free and open-source while protecting the rights of users.

**Key Points**:
- Users can modify and redistribute the code.
- All modifications must be shared under the same GPL-3.0 license.

### Creative Commons Attribution 4.0 International License (CC BY 4.0)

The CC BY 4.0 license allows users to use the material in any way they choose, as long as they provide appropriate credit to the original author. This license is more flexible and can be applied to both open-source and proprietary projects.

**Key Points**:
- Users can use, modify, and distribute the software in any form.
- Users must give credit to the original author, Jaytirth Kundan.

## Author

**Jaytirth Kundan** (2024)

For any questions or suggestions, feel free to open an issue in the repository.

---
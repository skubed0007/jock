use std::{
    env::args,
    fs::{self, File},
    io::{self, stdin, stdout, BufWriter, Write},
    path::{Path, PathBuf},
};

use indicatif::{ProgressBar, ProgressStyle};

#[derive(Debug)]
pub enum JockError {
    Io(io::Error),
    PathNotFound(PathBuf),
    InvalidFormat,
    EncryptionNotAllowedForFolder,
}

const EXTENSION_SIZE: usize = 5;
const BUFFER_SIZE: usize = 8192; // Buffer size for file operations

fn main() {
    let args: Vec<String> = args().collect();
    
    // Check for help flag or insufficient arguments
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
        _ => eprintln!("Invalid command. Use 'lock' to encrypt or 'open' to decrypt.\nYou gave me: {}", command),
    }
}

// Help function to print usage information
fn print_help() {
    println!("Usage: jock <command> <password> <file_path>");
    println!("Commands:");
    println!("  lock         Encrypts the specified file using the provided password.");
    println!("  open         Decrypts the specified file using the provided password.");
    println!("  cli          Enter interactive mode for encrypting or decrypting messages.");
    println!("Options:");
    println!("  --help, -h   Show this help message.");
    println!("\nExamples:");
    println!("  jock lock mypassword /path/to/myfile.txt");
    println!("  jock open mypassword /path/to/myfile.jock");
    println!("  jock cli");
}

fn hash_password(password: &[u8]) -> Vec<u8> {
    password.iter().map(|&b| b.wrapping_mul(3).wrapping_add(7)).collect()
}

fn encrypt(data: &[u8], hashed_password: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &byte)| byte.wrapping_add(hashed_password[i % hashed_password.len()]))
        .collect()
}

fn decrypt(data: &[u8], hashed_password: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &byte)| byte.wrapping_sub(hashed_password[i % hashed_password.len()]))
        .collect()
}

fn encrypt_file(path: &Path, hashed_password: &[u8], output_file: &str) -> Result<(), JockError> {
    let data = fs::read(&path).map_err(JockError::Io)?;
    let total_size = data.len();
    let encrypted_data = encrypt(&data, hashed_password);

    // Create progress bar
    let pb = ProgressBar::new(total_size as u64);
    pb.set_style(ProgressStyle::with_template("{msg} {bar:40} {bytes}/{total_bytes} ({eta})").unwrap());

    // Write encrypted data to output file
    let mut output = BufWriter::new(File::create(output_file).map_err(JockError::Io)?);
    let mut bytes_written = 0;

    // Write data in chunks
    while bytes_written < encrypted_data.len() {
        let chunk_size = std::cmp::min(BUFFER_SIZE, encrypted_data.len() - bytes_written);
        output.write_all(&encrypted_data[bytes_written..bytes_written + chunk_size]).map_err(JockError::Io)?;
        bytes_written += chunk_size;

        // Update progress bar
        pb.set_message("Encrypting...");
        pb.set_position(bytes_written as u64);
    }

    // Finalize progress bar
    pb.finish_with_message("Encryption complete!");

    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    let extension_bytes = extension.as_bytes();
    let extension_len = extension_bytes.len().min(EXTENSION_SIZE);

    // Write the file extension
    let mut extension_buffer = vec![0u8; EXTENSION_SIZE];
    extension_buffer[..extension_len].copy_from_slice(&extension_bytes[..extension_len]);
    output.write_all(&extension_buffer).map_err(JockError::Io)?;

    // Delete the original file after successful encryption
    fs::remove_file(path).map_err(JockError::Io)?;
    println!("Original file deleted after encryption.");

    Ok(())
}

fn decrypt_file(encrypted_file: &Path, hashed_password: &[u8]) -> Result<(), JockError> {
    let data = fs::read(encrypted_file).map_err(JockError::Io)?;
    let total_size = data.len();

    // Read the extension and decrypt the data
    let extension_bytes = if total_size >= EXTENSION_SIZE {
        &data[(total_size - EXTENSION_SIZE)..]
    } else {
        &data[..total_size]
    };

    let extension_length = extension_bytes.iter().position(|&b| b == 0).unwrap_or(extension_bytes.len());
    let file_extension = std::str::from_utf8(&extension_bytes[..extension_length]).unwrap_or("");

    let decrypted_data = decrypt(&data[..total_size - EXTENSION_SIZE], hashed_password);

    // Create the new output file name by replacing the .jock extension with the retrieved extension
    let new_output_file = encrypted_file.with_extension(file_extension);

    // Create progress bar for decryption
    let pb = ProgressBar::new(decrypted_data.len() as u64);
    pb.set_style(ProgressStyle::with_template("{msg} {bar:40} {bytes}/{total_bytes} ({eta})").unwrap());

    // Write the decrypted data to the new file
    let mut output = BufWriter::new(File::create(&new_output_file).map_err(JockError::Io)?);
    let mut bytes_written = 0;

    // Write data in chunks
    while bytes_written < decrypted_data.len() {
        let chunk_size = std::cmp::min(BUFFER_SIZE, decrypted_data.len() - bytes_written);
        output.write_all(&decrypted_data[bytes_written..bytes_written + chunk_size]).map_err(JockError::Io)?;
        bytes_written += chunk_size;

        // Update progress bar
        pb.set_message("Decrypting...");
        pb.set_position(bytes_written as u64);
    }

    // Finalize progress bar
    pb.finish_with_message("Decryption complete!");

    // Delete the original encrypted file
    fs::remove_file(encrypted_file).map_err(JockError::Io)?;
    println!("Encrypted file deleted after decryption.");

    println!("Decrypted file created: '{}'", new_output_file.display());
    Ok(())
}

fn climode() {
    loop {
        println!("\n=================================");
        println!(" Welcome to the Encryption System ");
        println!("=================================");
        
        println!("Please choose an action:");
        println!("1. Encrypt a message");
        println!("2. Decrypt a message");
        println!("3. Exit");
        print!("> ");
        stdout().flush().unwrap();

        let mut choice = String::new();
        stdin().read_line(&mut choice).unwrap();
        
        match choice.trim() {
            "1" => {
                println!("Enter the message to encrypt:");
                print!("> ");
                stdout().flush().unwrap();
                let mut msg = String::new();
                stdin().read_line(&mut msg).unwrap();

                println!("Enter your password for encryption:");
                print!("> ");
                stdout().flush().unwrap();
                let mut password = String::new();
                stdin().read_line(&mut password).unwrap();

                let hashed_password = hash_password(password.trim().as_bytes());
                let encrypted_msg = encrypt(msg.trim().as_bytes(), &hashed_password);

                println!("\n===============================");
                println!(" Encrypted Message ");
                println!("===============================\n");
                println!("{:?}", String::from_utf8_lossy(&encrypted_msg));
                println!("\n===============================");
            }
            "2" => {
                println!("Enter the encrypted message:");
                print!("> ");
                stdout().flush().unwrap();
                let mut encrypted_msg = String::new();
                stdin().read_line(&mut encrypted_msg).unwrap();

                println!("Enter your password for decryption:");
                print!("> ");
                stdout().flush().unwrap();
                let mut password = String::new();
                stdin().read_line(&mut password).unwrap();

                let hashed_password = hash_password(password.trim().as_bytes());
                
                // Decrypting the message
                let decrypted_msg = decrypt(encrypted_msg.trim().as_bytes(), &hashed_password);
                println!("{:?}", decrypted_msg);
                println!("\n===============================");
                println!(" Decrypted Message ");
                println!("===============================\n");
                println!("{}", String::from_utf8_lossy(&decrypted_msg));
                println!("\n===============================");
            }
            "3" => {
                println!("Exiting the program. Goodbye!");
                break;
            }
            _ => {
                println!("Invalid option, please try again.");
            }
        }
    }
}

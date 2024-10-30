use std::{
    env::args,
    fs::{self, File},
    io::{self, stdout, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use indicatif::ProgressBar; // Import ProgressBar for spinner

#[derive(Debug)]
pub enum JockError {
    Io(io::Error),
    InvalidCommand(String),
    PathNotFound(PathBuf),
    OutputError(String),
    CryptoError,
}

fn main() {
    clear_screen(); // Clear the screen at the start

    let a: Vec<String> = args().collect();

    // Check for help or incorrect argument count
    if a.len() < 2 || a[1] == "--help" || a[1] == "-h" {
        print_help();
        return;
    }

    let cmd = &a[1];

    match cmd.as_str() {
        "lock" | "open" => {
            if a.len() < 4 {
                eprintln!("Error: Missing password or target.");
                return;
            }
            let pwd = a[2].as_bytes();
            let targets: Vec<&str> = a[3..].iter().map(|s| s.as_str()).collect();
            let hp = hash_password(pwd);

            let op = if a.len() >= 6 && a[4] == "--output" {
                Some(a[5].clone())
            } else {
                None
            };

            // Process each target
            for tgt in targets {
                match cmd.as_str() {
                    "lock" => {
                        if let Err(e) = process_target(tgt, &hp, true, op.clone()) {
                            eprintln!("Error processing target '{}': {:?}", tgt, e);
                        }
                    }
                    "open" => {
                        if let Err(e) = process_target(tgt, &hp, false, op.clone()) {
                            eprintln!("Error processing target '{}': {:?}", tgt, e);
                        }
                    }
                    _ => {
                        let error = JockError::InvalidCommand(cmd.clone());
                        eprintln!("Error: {:?}", error);
                    }
                }
            }
        }
        "cli" => {
            handle_cli(); // Directly call the CLI mode without additional arguments
        }
        _ => {
            let error = JockError::InvalidCommand(cmd.clone());
            eprintln!("Error: {:?}", error);
        }
    }
}

fn print_help() {
    println!("\nUsage: jock <lock|open|cli> <password> <file_or_folder_or_message>... [--output <output_file>]");
    println!("Commands:");
    println!("  lock         Encrypts the specified files, folders, or messages using the provided password.");
    println!("  open         Decrypts the specified files or folders using the provided password.");
    println!("  cli          Encrypts or decrypts messages interactively.");
    println!("Arguments:");
    println!("  <password>   A password to secure your encryption or decryption process.");
    println!("  <file_or_folder_or_message> The paths of files or folders to encrypt or decrypt, or messages to encrypt.");
    println!("Options:");
    println!("  --output <output_file> Specify a custom output file path. If not provided, the original files will be saved with the .jock extension.");
    println!("Example:");
    println!("  jock lock mypassword /path/to/file1 /path/to/file2 \"This is a message\" --output /path/to/encrypted_file");
}

fn hash_password(p: &[u8]) -> Vec<u8> {
    p.iter().map(|&b| b.wrapping_mul(3).wrapping_add(7)).collect()
}

fn encrypt(data: &[u8], hp: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b.wrapping_add(hp[i % hp.len()]))
        .collect()
}

fn decrypt(data: &[u8], hp: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b.wrapping_sub(hp[i % hp.len()]))
        .collect()
}

fn handle_cli() {
    clear_screen(); // Clear the screen when entering CLI mode
    let stdin = io::stdin();
    loop {
        let mut input = String::new();
        println!("Enter a message to encrypt or decrypt (or 'exit' to quit):");
        print!("> ");
        stdout().flush().unwrap();
        stdin.read_line(&mut input).expect("Failed to read line");
        let input = input.trim();

        if input.eq_ignore_ascii_case("exit") {
            break; // Exit the loop if the user types 'exit'
        }

        // Prompt for action
        println!("Choose action (lock to encrypt / open to decrypt):");
        print!("> ");
        stdout().flush().unwrap();

        let mut action = String::new();
        stdin.read_line(&mut action).expect("Failed to read line");
        let action = action.trim();

        match action {
            "lock" => {
                println!("Enter password for encryption:");
                print!("> ");
                stdout().flush().unwrap();

                let mut password = String::new();
                stdin.read_line(&mut password).expect("Failed to read line");
                let hp = hash_password(password.trim().as_bytes());
                let encrypted_message = encrypt(input.as_bytes(), &hp);
                let output = String::from_utf8_lossy(&encrypted_message);
                println!("Encrypted message: {}", output);
            }
            "open" => {
                println!("Enter password for decryption:");
                print!("{}","> ");
                stdout().flush().unwrap();

                let mut password = String::new();
                stdin.read_line(&mut password).expect("Failed to read line");
                let hp = hash_password(password.trim().as_bytes());
                let decrypted_message = decrypt(input.as_bytes(), &hp);
                let output = String::from_utf8_lossy(&decrypted_message);
                println!("Decrypted message: {}", output);
            }
            _ => {
                eprintln!("Invalid action. Please type 'lock' or 'open'.");
            }
        }
    }
}

fn clear_screen() {
    // Clear the screen based on the operating system
    if let Ok(_) = Command::new("clear").status() {
        Command::new("clear").status().unwrap();
    } else {
        Command::new("cls").status().unwrap();
    }
}

fn process_target(tgt: &str, hp: &[u8], enc_mode: bool, op: Option<String>) -> Result<(), JockError> {
    let p = Path::new(tgt);
    let spinner = ProgressBar::new_spinner();

    if p.is_dir() {
        // Collect entries to avoid moving value
        let entries: Vec<_> = fs::read_dir(p).map_err(JockError::Io)?.collect();

        for entry in entries {
            let f_path = entry.map_err(JockError::Io)?.path();
            if f_path.is_file() {
                let output_file = op.clone().unwrap_or_else(|| {
                    let mut o = f_path.clone();
                    if enc_mode {
                        o.set_extension("jock");
                    }
                    o.to_string_lossy().into_owned()
                });

                spinner.set_message(format!("Processing file: '{}'", f_path.display()));
                spinner.enable_steady_tick(Duration::from_millis(50)); // Show steady spinning

                // Process each file without threading
                if let Err(e) = process_file(&f_path, hp, enc_mode, Some(output_file)) {
                    eprintln!(
                        "Error processing file '{}': {:?}",
                        f_path.display(),
                        e
                    );
                }

                // Finish the spinner
                spinner.finish_with_message(format!("Done processing file '{}'", f_path.display()));
            }
        }
    } else if p.is_file() {
        // Process the single file
        let output_file = op.clone().unwrap_or_else(|| {
            let mut o = p.to_path_buf();
            if enc_mode {
                o.set_extension("jock");
            }
            o.to_string_lossy().into_owned()
        });
        
        spinner.set_message(format!("Processing file: '{}'", p.display()));
        spinner.enable_steady_tick(Duration::from_millis(50)); // Show steady spinning

        if let Err(e) = process_file(p, hp, enc_mode, Some(output_file)) {
            eprintln!(
                "Error processing file '{}': {:?}",
                p.display(),
                e
            );
        }

        // Finish the spinner
        spinner.finish_with_message(format!("Done processing file '{}'", p.display()));
    } else {
        // If the target is not a path, treat it as a message
        if enc_mode {
            // If locking, encrypt the message
            let encrypted_message = encrypt(tgt.as_bytes(), hp);
            let output = String::from_utf8_lossy(&encrypted_message);
            println!("Encrypted message: {}", output);
        } else {
            // If opening, we cannot decrypt a message without a file
            return Err(JockError::PathNotFound(p.to_path_buf()));
        }
    }
    Ok(())
}

fn process_file(fp: &Path, hp: &[u8], enc_mode: bool, mut opf: Option<String>) -> Result<(), JockError> {
    let spinner = ProgressBar::new_spinner();
    spinner.set_message(format!("Reading file: '{}'", fp.display()));
    spinner.enable_steady_tick(Duration::from_millis(50)); // Show steady spinning

    let mut f = BufReader::new(File::open(fp).map_err(JockError::Io)?);
    let mut data = Vec::new();
    let _total_size = f.read_to_end(&mut data).map_err(JockError::Io)?;
    spinner.finish_with_message("File read successfully.");

    // Choose to encrypt or decrypt based on enc_mode
    let output = if enc_mode {
        spinner.set_message("Encrypting data...");
        let mut enc_data = encrypt(&data, hp);
        if let Some(ext) = fp.extension() {
            let ext_data = format!("\0{}", ext.to_string_lossy());
            enc_data.extend_from_slice(ext_data.as_bytes());
        }
        enc_data
    } else {
        spinner.set_message("Decrypting data...");
        let mut dec_data = decrypt(&data[..data.len() - 1], hp);
        let ext_start = data.len().saturating_sub(1024);
        if let Some(delim_index) = data[ext_start..].iter().rposition(|&x| x == 0) {
            let orig_ext = String::from_utf8_lossy(&data[ext_start + delim_index + 1..]).to_string();
            dec_data.truncate(ext_start + delim_index);
            if let Some(ref mut out_path) = opf {
                out_path.push_str(&format!(".{}", orig_ext));
            }
        }
        dec_data
    };

    // Write output to the specified file
    if let Some(out_fp) = opf {
        spinner.set_message(format!("Writing output to: '{}'", out_fp));
        let mut out = BufWriter::new(File::create(&out_fp).map_err(JockError::Io)?);
        out.write_all(&output).map_err(JockError::Io)?;
        spinner.finish_with_message("Output written successfully.");
    } else {
        return Err(JockError::OutputError("No output file specified.".into()));
    }

    Ok(())
}

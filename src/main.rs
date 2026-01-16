//! ejson2env CLI - Export environment variables from EJSON and EYAML files.

use std::io;
use std::process::exit;

use clap::Parser;
use zeroize::Zeroizing;

use ejson2env::{
    export_env, export_quiet, read_and_export_env, read_key_from_stdin, ExportFunction,
};

/// Get environment variables from ejson/eyaml files.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Directory containing EJSON keys
    #[arg(
        short = 'k',
        long,
        default_value = "/opt/ejson/keys",
        env = "EJSON_KEYDIR"
    )]
    keydir: String,

    /// Read the private key from STDIN
    #[arg(long)]
    key_from_stdin: bool,

    /// Suppress export statement
    #[arg(short, long)]
    quiet: bool,

    /// Trim the first leading underscore from variable names
    #[arg(long)]
    trim_underscore_prefix: bool,

    /// The ejson/eyaml file to process
    filename: Option<String>,
}

fn fail(err: &str) -> ! {
    eprintln!("error: {}", err);
    exit(1);
}

fn main() {
    let args = Args::parse();

    // Get the filename
    let filename = match args.filename {
        Some(f) => f,
        None => fail("no secrets.ejson/secrets.eyaml filename passed"),
    };

    // Read private key from stdin if requested
    // Using Zeroizing to ensure the key is securely wiped from memory when dropped
    let user_supplied_private_key: Zeroizing<String> = if args.key_from_stdin {
        match read_key_from_stdin() {
            Ok(key) => key,
            Err(e) => fail(&format!("failed to read from stdin: {}", e)),
        }
    } else {
        Zeroizing::new(String::new())
    };

    // Select the export function based on flags
    let export_func: ExportFunction = if args.quiet { export_quiet } else { export_env };

    // Get stdout handle
    let mut stdout = io::stdout();

    // Execute with the trim flag passed to the library
    if let Err(e) = read_and_export_env(
        &filename,
        &args.keydir,
        &user_supplied_private_key,
        args.trim_underscore_prefix,
        export_func,
        &mut stdout,
    ) {
        fail(&e.to_string());
    }
}

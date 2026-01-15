//! ejson2env CLI - Export environment variables from EJSON and EYAML files.

use std::io;
use std::process::exit;

use clap::Parser;

use ejson2env::{
    export_env, export_quiet, read_and_export_env, read_key_from_stdin, trim_leading_underscores,
    trim_underscore_prefix, ExportFunction,
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

    /// Trim all leading underscores from variable names (deprecated, use --trim-underscore-prefix)
    #[arg(long)]
    trim_underscore: bool,

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
    let user_supplied_private_key = if args.key_from_stdin {
        match read_key_from_stdin() {
            Ok(key) => key,
            Err(e) => fail(&format!("failed to read from stdin: {}", e)),
        }
    } else {
        String::new()
    };

    // Select the export function based on flags
    let base_export_func: ExportFunction = if args.quiet { export_quiet } else { export_env };

    // Get stdout handle
    let mut stdout = io::stdout();

    // Execute based on trim flags
    if args.trim_underscore_prefix || args.trim_underscore {
        let result =
            ejson2env::read_and_extract_env(&filename, &args.keydir, &user_supplied_private_key);

        match result {
            Ok(env_values) => {
                let trimmed = if args.trim_underscore_prefix {
                    trim_underscore_prefix(&env_values)
                } else {
                    trim_leading_underscores(&env_values)
                };
                base_export_func(&mut stdout, &trimmed);
            }
            Err(e) if ejson2env::is_env_error(&e) => {
                // No env or bad env is not a fatal error
                base_export_func(&mut stdout, &std::collections::BTreeMap::new());
            }
            Err(e) => fail(&format!("could not load environment from file: {}", e)),
        }
    } else if let Err(e) = read_and_export_env(
        &filename,
        &args.keydir,
        &user_supplied_private_key,
        base_export_func,
        &mut stdout,
    ) {
        fail(&e.to_string());
    }
}

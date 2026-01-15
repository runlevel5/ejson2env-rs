# ejson2env-rs

A Rust port of [Shopify/ejson2env](https://github.com/Shopify/ejson2env) for exporting encrypted EJSON secrets as shell environment variables. Drop-in replacement with the same CLI interface.

## What It Does

Reads an EJSON file, decrypts the `environment` object, and outputs shell export statements.

**Input** (`secrets.ejson`):
```json
{
    "_public_key": "<public key>",
    "environment": {
        "DATABASE_URL": "<encrypted>",
        "API_KEY": "<encrypted>"
    }
}
```

**Output**:
```shell
export API_KEY='decrypted-api-key'
export DATABASE_URL='decrypted-database-url'
```

> **Shell Compatibility:** This tool generates `export` statements, which are supported by POSIX-compatible shells such as **bash**, **zsh**, **sh**, and **ksh**. It is not compatible with shells that use different syntax for environment variables (e.g., fish, csh, tcsh).

## Installation

### From Source

```shell
git clone https://github.com/runlevel5/ejson2env-rs.git
cd ejson2env-rs
cargo build --release
cp ./target/release/ejson2env ~/.local/bin/
```

### Pre-built Binaries

Download from [Releases](https://github.com/runlevel5/ejson2env-rs/releases).

> **Note:** No Homebrew, Deb, or RPM packages yet. Contributions welcome!

## Usage

### Basic Usage

```shell
# Output export statements
ejson2env secrets.ejson

# Load secrets into current shell
eval $(ejson2env secrets.ejson)
```

### Options

```
ejson2env [OPTIONS] <FILE>

Options:
  -k, --keydir <DIR>     Directory containing EJSON keys [default: /opt/ejson/keys]
                         Can also be set via EJSON_KEYDIR env var
      --key-from-stdin   Read the private key from stdin
  -q, --quiet            Omit "export" prefix (output: KEY='value')
      --trim-underscore  Remove leading underscores from variable names
  -h, --help             Print help
  -V, --version          Print version
```

### Examples

```shell
# Use a custom key directory
ejson2env -k /path/to/keys secrets.ejson

# Pipe key from another source
cat /path/to/private.key | ejson2env --key-from-stdin secrets.ejson

# Output without "export" prefix (useful for .env files)
ejson2env -q secrets.ejson > .env

# Strip leading underscores from variable names
# _SECRET_KEY becomes SECRET_KEY
ejson2env --trim-underscore secrets.ejson
```

## Key Management

EJSON uses public-key cryptography. The private key must be available at decryption time:

1. **File-based** (default): Place the private key in a file named after the public key in the keydir (e.g., `/opt/ejson/keys/<public_key>`)
2. **Stdin**: Pass via `--key-from-stdin`
3. **Environment**: Set `EJSON_KEYDIR` to override the default key directory

## Related Projects

- [ejson](https://github.com/Shopify/ejson) - Original EJSON tool by Shopify
- [ejson-rs](https://github.com/runlevel5/ejson-rs) - Rust EJSON library this tool is built on

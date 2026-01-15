# ejson2env-rs

A Rust port of [Shopify/ejson2env](https://github.com/Shopify/ejson2env) for exporting encrypted EJSON/EYAML/ETOML secrets as shell environment variables. Drop-in replacement with the same CLI interface, plus added support for YAML and TOML formats.

## What It Does

Reads an EJSON, EYAML, or ETOML file, decrypts the `environment` object, and outputs shell export statements.

**Input** (`secrets.ejson`):
```json
{
    "_public_key": "<public key>",
    "environment": {
        "DATABASE_URL": "<encrypted>",
        "API_KEY": "<encrypted>",
        "_ENVIRONMENT": "production"
    }
}
```

**Or** (`secrets.eyaml`):
```yaml
_public_key: "<public key>"
environment:
  DATABASE_URL: "<encrypted>"
  API_KEY: "<encrypted>"
  _ENVIRONMENT: production
```

**Or** (`secrets.etoml`):
```toml
_public_key = "<public key>"

[environment]
DATABASE_URL = "<encrypted>"
API_KEY = "<encrypted>"
_ENVIRONMENT = "production"
```

**Output**:
```shell
export API_KEY='decrypted-api-key'
export DATABASE_URL='decrypted-database-url'
export _ENVIRONMENT='production'
```

> **Underscore Prefix:** Keys prefixed with `_` (e.g., `_ENVIRONMENT`) are left **unencrypted** in the secrets file. This is useful for non-sensitive configuration values that you want to keep readable. Use `--trim-underscore-prefix` to strip the first leading underscore from variable names in the output (e.g., `_ENVIRONMENT` becomes `ENVIRONMENT`, but `__DOUBLE` becomes `_DOUBLE`).

> **Shell Compatibility:** This tool generates `export` statements, which are supported by POSIX-compatible shells such as **bash**, **zsh**, **sh**, and **ksh**. It is not compatible with shells that use different syntax for environment variables (e.g., fish, csh, tcsh).

## Supported File Formats

Format detection is automatic based on file extension:

| Format | Extensions |
|--------|------------|
| JSON   | `.ejson`, `.json` |
| YAML   | `.eyaml`, `.yaml`, `.yml` |
| TOML   | `.etoml`, `.toml` |

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
# Output export statements (EJSON)
ejson2env secrets.ejson

# Output export statements (EYAML)
ejson2env secrets.eyaml

# Output export statements (ETOML)
ejson2env secrets.etoml

# Load secrets into current shell
eval $(ejson2env secrets.ejson)
eval $(ejson2env secrets.eyaml)
eval $(ejson2env secrets.etoml)
```

### Options

```
ejson2env [OPTIONS] <FILE>

Options:
  -k, --keydir <DIR>     Directory containing EJSON keys [default: /opt/ejson/keys]
                         Can also be set via EJSON_KEYDIR env var
      --key-from-stdin   Read the private key from stdin
  -q, --quiet            Omit "export" prefix (output: KEY='value')
      --trim-underscore-prefix  Remove the first leading underscore from variable names
                                (e.g., _ENVIRONMENT becomes ENVIRONMENT, __KEY becomes _KEY)
      --trim-underscore  Remove all leading underscores from variable names
                         (e.g., __KEY becomes KEY) [deprecated: use --trim-underscore-prefix]
  -h, --help             Print help
  -V, --version          Print version
```

### Examples

#### EJSON

```shell
# Use a custom key directory
ejson2env -k /path/to/keys secrets.ejson

# Pipe key from another source
cat /path/to/private.key | ejson2env --key-from-stdin secrets.ejson

# Output without "export" prefix (useful for .env files)
ejson2env -q secrets.ejson > .env

# Strip leading underscores from variable names
# Useful when you have unencrypted keys like _ENVIRONMENT that should
# be exported as ENVIRONMENT (without the underscore prefix)
ejson2env --trim-underscore-prefix secrets.ejson
```

#### EYAML

```shell
# Use a custom key directory
ejson2env -k /path/to/keys secrets.eyaml

# Pipe key from another source
cat /path/to/private.key | ejson2env --key-from-stdin secrets.eyaml

# Output without "export" prefix (useful for .env files)
ejson2env -q secrets.eyaml > .env

# Strip leading underscores from variable names
# Useful when you have unencrypted keys like _ENVIRONMENT that should
# be exported as ENVIRONMENT (without the underscore prefix)
ejson2env --trim-underscore-prefix secrets.eyaml
```

#### ETOML

```shell
# Use a custom key directory
ejson2env -k /path/to/keys secrets.etoml

# Pipe key from another source
cat /path/to/private.key | ejson2env --key-from-stdin secrets.etoml

# Output without "export" prefix (useful for .env files)
ejson2env -q secrets.etoml > .env

# Strip leading underscores from variable names
# Useful when you have unencrypted keys like _ENVIRONMENT that should
# be exported as ENVIRONMENT (without the underscore prefix)
ejson2env --trim-underscore-prefix secrets.etoml
```

## Key Management

EJSON uses public-key cryptography. The private key must be available at decryption time:

1. **File-based** (default): Place the private key in a file named after the public key in the keydir (e.g., `/opt/ejson/keys/<public_key>`)
2. **Stdin**: Pass via `--key-from-stdin`
3. **Environment**: Set `EJSON_KEYDIR` to override the default key directory

## Related Projects

- [ejson](https://github.com/Shopify/ejson) - Original EJSON tool by Shopify
- [ejson-rs](https://github.com/runlevel5/ejson-rs) - Rust EJSON library this tool is built on (supports JSON, YAML, and TOML)

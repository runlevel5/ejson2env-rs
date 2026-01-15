# ejson2env-rs

This is the Rust port of `Shopify/ejson2env`. It could be used as drop-in replacement since it shares the same interface.

`ejson2env-rs` is a tool to simplify storing secrets that should be accessible in the shell environment in your git repo. It is based on the [ejson-rs library](https://github.com/runlevel5/ejson-rs) and extends the `ejson` file format.

It exports all of the values in the `environment` object in the `ejson` file to the shell environment.

For example, with the below `ejson` file:

```json
{
    "_public_key": "<public key here>",
    "environment": {
        "SECRET_SHELL_VARIABLE": "<encrypted data>"
    }
}
```

Running:

```shell
$ ejson2env test.ejson
```

Would result in the following output:

```
export SECRET_SHELL_VARIABLE=<decrypted data>
```

You can then have your shell evaluate this output:

```shell
$ eval $(ejson2env test.ejson)
```

## Using ejson2env

`ejson2env`'s usage information is described in it's included `--help` flag.

## Installing ejson2env

Grab the pre-built binary from Releases page

Alternatively it could be built from scratch:

```sh
git clone https://github.com/runlevel5/ejson2env-rs.git
cd ejson2env-rs
cargo build --release
cp ./target/release/ejson2env ~/.local/bin/
```

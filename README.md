# RTR Validator

A simple Rust CLI tool to validate IP prefixes against an RTR (RPKI-to-Router) server.

## Features

- Connect to any RTR server
- Validate IPv4 and IPv6 prefixes
- Check if a specific ASN is authorized to announce a prefix
- Display all ROAs matching a given prefix

## Installation

```bash
cargo build --release
```

## Usage

### Basic prefix validation

Check if a prefix has any ROAs:

```bash
cargo run -- --server "[2a06:de00:50:cafe:100::e]:3323" --prefix "2001:db8::/32"
```

### Validate prefix with ASN

Check if a specific ASN is authorized to announce a prefix:

```bash
cargo run -- --server "[2a06:de00:50:cafe:100::e]:3323" --prefix "2001:db8::/32" --asn 64496
```

### IPv4 example

```bash
cargo run -- --server "[2a06:de00:50:cafe:100::e]:3323" --prefix "192.0.2.0/24" --asn 64496
```

## Examples

### Valid prefix with authorized ASN
```
$ cargo run -- -s "[2a06:de00:50:cafe:100::e]:3323" -p "2001:db8::/32" -a 64496

Connecting to RTR server at [2a06:de00:50:cafe:100::e]:3323...
Connected! Fetching ROAs...

Total ROAs received: 250000
Validation results for prefix: 2001:db8::/32

✅ FOUND - 1 matching ROA(s):
  - AS64496 (max length: 48)

✅ VALID - AS64496 is authorized to announce 2001:db8::/32
```

### Invalid prefix (no ROA)
```
$ cargo run -- -s "[2a06:de00:50:cafe:100::e]:3323" -p "2001:db8:bad::/48"

Connecting to RTR server at [2a06:de00:50:cafe:100::e]:3323...
Connected! Fetching ROAs...

Total ROAs received: 250000
Validation results for prefix: 2001:db8:bad::/48

❌ NOT FOUND - No ROA found for this prefix
Status: INVALID (prefix not authorized in RPKI)
```

### Wrong ASN for prefix
```
$ cargo run -- -s "[2a06:de00:50:cafe:100::e]:3323" -p "2001:db8::/32" -a 99999

Connecting to RTR server at [2a06:de00:50:cafe:100::e]:3323...
Connected! Fetching ROAs...

Total ROAs received: 250000
Validation results for prefix: 2001:db8::/32

✅ FOUND - 1 matching ROA(s):
  - AS64496 (max length: 48)

❌ INVALID - AS99999 is NOT authorized to announce 2001:db8::/32
Authorized ASNs: ["AS64496"]
```

## Command-line Options

- `-s, --server <SERVER>` - RTR server address (e.g., `[2a06:de00:50:cafe:100::e]:3323`)
- `-p, --prefix <PREFIX>` - IP prefix to validate (e.g., `2001:db8::/32` or `192.0.2.0/24`)
- `-a, --asn <ASN>` - Optional ASN to check authorization (e.g., `64496`)

## How it works

1. Connects to the RTR server via TCP
2. Performs RTR protocol handshake using the `rpki` crate
3. Downloads all ROAs (Route Origin Authorizations) via the RTR protocol
4. Searches for ROAs matching the specified prefix
5. If an ASN is provided, checks if it's authorized
6. Displays validation results

## Testing with your Routinator instance

```bash
# Test with a real prefix (e.g., Cloudflare's 1.1.1.0/24)
cargo run --release -- -s "[2a06:de00:50:cafe:100::e]:3323" -p "1.1.1.0/24"

# Test with ASN validation
cargo run --release -- -s "[2a06:de00:50:cafe:100::e]:3323" -p "1.1.1.0/24" -a 13335
```

## Dependencies

- `rpki` - RPKI library with RTR protocol client support
- `tokio` - Async runtime for network I/O
- `clap` - Command-line argument parsing
- `anyhow` - Error handling
- `ipnet` - IP network types
- `bytes` - Byte buffer utilities

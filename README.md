# RTR Validator

Validate IP prefixes against an RTR (RPKI-to-Router) server.

## Installation

```bash
cargo install --path .
```

## Usage

```bash
rtr-validator --server <SERVER> --prefix <PREFIX> [OPTIONS]
```

### Examples

```bash
# Check if a prefix has any ROAs (default 30s timeout)
rtr-validator -s "rtr.nxthdr.dev:3323" -p "1.1.1.0/24"

# Validate with specific ASN
rtr-validator -s "rtr.nxthdr.dev:3323" -p "1.1.1.0/24" -a 13335

# Use longer timeout for slower connections
rtr-validator -s "rtr.nxthdr.dev:3323" -p "1.1.1.0/24" -t 60

# IPv6 example
rtr-validator -s "rtr.nxthdr.dev:3323" -p "2606:4700:4700::/48" -a 13335
```

### Output

```
Connecting to RTR server at [2a06:de00:50:cafe:100::e]:3323...
Connected! Fetching ROAs (timeout: 30s)...

RTR sync timeout (expected) - extracting collected ROAs
Total ROAs received: 785041

Validation results for prefix: 1.1.1.0/24

✅ FOUND - 1 matching ROA(s):
  - AS13335 (max length: 24)
```

## Options

- `-s, --server` - RTR server address (hostname:port or [ipv6]:port)
- `-p, --prefix` - IP prefix to validate (IPv4 or IPv6)
- `-a, --asn` - ASN to check (optional)
- `-t, --timeout` - Timeout in seconds for RTR sync (default: 30)

# RTR Validator

Validate IP prefixes against an RTR (RPKI-to-Router) server.

## Installation

```bash
cargo install --path .
```

## Usage

```bash
rtr-validator --server <SERVER> --prefix <PREFIX> [--asn <ASN>]
```

### Examples

```bash
# Check if a prefix has any ROAs
rtr-validator -s "rtr.nxthdr.dev:3323" -p "1.1.1.0/24"

# Validate with specific ASN
rtr-validator -s "rtr.nxthdr.dev:3323" -p "1.1.1.0/24" -a 13335

# IPv6 example
rtr-validator -s "rtr.nxthdr.dev:3323" -p "2606:4700:4700::/48" -a 13335
```

### Output

```
Connecting to RTR server at [2a06:de00:50:cafe:100::e]:3323...
Connected! Fetching ROAs until End of Data marker...

End of Data received - initial sync complete
Total ROAs received: 784793

Validation results for prefix: 1.1.1.0/24

✅ FOUND - 1 matching ROA(s):
  - AS13335 (max length: 24)
```

## How it works

The tool connects to the RTR server and downloads all ROAs until the RTR protocol's **End of Data (EOD)** marker is received. This ensures complete data synchronization before performing validation. The EOD marker is detected via the `Timing` parameters sent in the End-of-Data PDU.

## Options

- `-s, --server` - RTR server address (hostname:port or [ipv6]:port)
- `-p, --prefix` - IP prefix to validate (IPv4 or IPv6)
- `-a, --asn` - ASN to check (optional)

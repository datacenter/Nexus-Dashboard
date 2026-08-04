# NDP Plugin Development

Build and package Nexus Dashboard Plugin (`.ndp`) archives for use with `acs plugin` commands.

## Overview

An `.ndp` file is a gzip-compressed tar archive containing:

| File | Purpose |
|------|---------|
| `manifest.yaml` | Plugin metadata (name, version, entry point, etc.) |
| `manifest.yaml.signature` | Abraxas/SWIMS cryptographic signature of the manifest |
| `run.sh` | Entry point script executed by `acs plugin run` |
| `ND-Preupgrade-Validation.py` | Main validation script |
| `worker_functions.py` | Worker script deployed to each node |

The ND node verifies the signature against Abraxas public keys at
`/certs/signing/{dev,rel}.pem` before allowing installation. These keys
originate from the **ACI** SWIMS key identity (same keys used for SMU/ISO
signing), so the plugin Makefile uses `PROJECT=aci` to match.

## Directory Structure

```
plugin/
├── Makefile                          # Build system
├── README.md                         # This file
├── .gitignore
├── keys/                             # Local test keys (not committed)
├── pre-upgrade-validation/           # Plugin source
│   ├── manifest.yaml                 # Plugin metadata
│   └── run.sh                        # Entry point
├── .build-env/                       # Cloned build repo (not committed)
│   ├── tools/code_sign.sh
│   └── swims/                        # SWIMS tokens
└── dist/                             # Built .ndp files (not committed)
```

## Manifest Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Plugin identifier (e.g. `nd-preupgrade-validation`) |
| `version` | Yes | Version string (e.g. `"1.0.0"`) |
| `description` | Yes | Human-readable description |
| `min_nd_version` | Yes | Minimum ND version required (e.g. `"4.3"`) |
| `entry_point` | Yes | Relative path to the executable entry point (e.g. `run.sh`) |

## Building

### Prerequisites

- GNU Make
- `openssl` CLI (for local signing)
- `git` (for `make setup` to clone the build repo)
- Artifactory credentials for SWIMS signing (see below)

### Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Package the plugin (unsigned — will fail verification on ND) |
| `make sign-local` | Build + sign with a local PEM key (offline dev testing) |
| `make dev` | Build + SWIMS dev sign |
| `make rel` | Build + SWIMS release sign |
| `make setup` | Clone build repo into `.build-env/` (one-time) |
| `make clean` | Remove build artifacts |
| `make distclean` | Remove build artifacts + `.build-env/` |

### Option 1: Local Signing (No SWIMS, for Development)

Use this when you just need to test the plugin lifecycle without real Abraxas keys.

```bash
# Generate a test keypair (one-time)
mkdir -p keys
openssl genpkey -algorithm RSA -out keys/dev.pem -pkeyopt rsa_keygen_bits:4096
openssl rsa -in keys/dev.pem -pubout -out keys/dev.pub.pem

# Build with local signing
make sign-local
```

To test on an ND node, replace the Abraxas public key on the box:

```bash
# On the ND node (as root):
cp /certs/signing/dev.pem /root/dev.pem.orig          # backup original
# Copy keys/dev.pub.pem to /certs/signing/dev.pem      # replace with your key

# When done testing:
cp /root/dev.pem.orig /certs/signing/dev.pem           # restore original
```

### Option 2: SWIMS Signing (Production)

Uses the same `code_sign.sh` + `code_sign.x86_64` infrastructure as ISO/OVA builds.
The Makefile clones the `build` repo and downloads tools from Artifactory automatically.

#### Step 1: One-time Setup

```bash
make setup
```

This clones the `build` repo into `.build-env/` and creates `.build-env/swims/` for tokens.

#### Step 2: SWIMS Tokens

SWIMS tokens are ephemeral. The easiest way to get them is to let `code_sign.sh init`
download them from Artifactory (they're bundled inside `code_sign.tar.gz`). After a
successful `make dev`, copy the fresh tokens from the extracted tarball:

```bash
cp .swims-staging/code_sign/.sec_id_new             .build-env/swims/
cp .swims-staging/code_sign/ACI_NEW_SWIMS_DEV.token .build-env/swims/
```

Alternatively, copy from a recent Jenkins build sandbox.

#### Step 3: Build

```bash
# Dev signing
make dev CODE_SIGN_CREDENTIALS=user:artifactory-token

# Release signing
make rel CODE_SIGN_CREDENTIALS=user:artifactory-token
```

`CODE_SIGN_CREDENTIALS` is your `username:identity-token` for
`artifactory.devhub-cloud.cisco.com`. The signing flow is:

1. `code_sign.sh init` — downloads `code_sign.x86_64` from Artifactory, establishes SWIMS session via Vault
2. `code_sign.sh bsign` — signs `manifest.yaml`, producing `manifest.yaml.signature`
3. `code_sign.sh destroy` — revokes the SWIMS session
4. Everything is packaged into `dist/<name>-<version>.ndp`

#### Matching Public Keys

The ND image ships with Abraxas public keys at `/certs/signing/{dev,rel}.pem`.
These are the **ACI** Abraxas keys (`AbraxasACIDev.pem` / `AbraxasACI.pem`),
checked into `bootmgr/shim/certs/` and `spm/cmd/firmwared/certs/`. They are
copied into the initrd at build time and then into `/certs/signing/` at boot
by `bootmgr`.

Because these are **committed, static** keys (not downloaded from SWIMS at
build time), they do not rotate with SWIMS key rotation. The plugin signing
uses `PROJECT=aci` so the SWIMS signing private key matches the committed
ACI public key on every ND box.

If you ever hit a signature mismatch (unlikely with committed keys), you can
extract and compare:

```bash
# Extract public key from the SWIMS ACI dev certificate
openssl x509 -in .build-env/swims/ACI_CODE_SIGN_RSA_DEV.PEM -pubkey -noout > /tmp/swims-dev.pub

# Compare with the key on the ND box:
diff /tmp/swims-dev.pub <(ssh root@<nd-node> cat /certs/signing/dev.pem)
```

## Testing on an ND Node

### Installing the Plugin

Host the `.ndp` file on a web server accessible from the ND node:

```bash
# From the ND node (as root or rescue-user):
acs plugin download http://<server>/<name>-<version>.ndp
```

Supported URL schemes: `http://`, `https://`, `scp://<host>:/<path>`, `file:///path`

### Plugin Lifecycle Commands

```bash
acs plugin show      # Display installed plugin metadata
acs plugin run       # Execute the plugin
acs plugin remove    # Uninstall the plugin
```

### Design Principle

NDP plugins should be self-contained — scripts or binaries inside the `.ndp`
archive should run without external dependencies on the ND node. ND boxes are
stripped-down Linux environments with no package manager.

### `sshpass` Note (pre-upgrade-validation only)

The `ND-Preupgrade-Validation.py` script specifically requires `sshpass` for
password-based SSH to cluster nodes. This is a dependency of the validation
script itself, not of the NDP framework. If you are packaging this script as
an `.ndp` to test the plugin system, `sshpass` must be present on the ND node:

```bash
# One-time transfer from a dev machine (repeat for each node in the cluster)
base64 /usr/bin/sshpass | ssh root@<nd-node> \
  "base64 -d > /usr/local/bin/sshpass && chmod +x /usr/local/bin/sshpass"
```

If `sshpass` is missing, `acs plugin run` will exit with a dependency error
for this particular plugin.

### What Happens on `acs plugin run`

The entry point `run.sh` is executed with `cwd` set to `/config/plugin/`. It:

1. Auto-detects the node's management IP via `hostname -I`
2. Reads the rescue-user password from `RESCUE_USER_PASS` environment variable
3. Runs `ND-Preupgrade-Validation.py` in non-interactive mode

Results are written to `/config/plugin/final-results/` and bundled into a `.tgz`.

### Environment Variables

`run.sh` respects these environment variables for override:

| Variable | Required | Description |
|----------|----------|-------------|
| `RESCUE_USER_PASS` | Yes | rescue-user password (no default; must be set) |
| `ND_IP` | No | ND management IP to validate against (auto-detected if omitted) |

## Running the Script Standalone (Without NDP)

The validation script can also be run directly from any Linux host with SSH access to
the ND cluster — no plugin packaging required:

```bash
cd script/

# Non-interactive (default) — fully automated
python3 ND-Preupgrade-Validation.py --ndip 10.1.1.1 -p <password>

# Interactive — prompted for all decisions
python3 ND-Preupgrade-Validation.py --ndip 10.1.1.1 -p <password> -i
```

See [`script/README.md`](../script/README.md) for full CLI options, checks performed,
and example output.

# NDP Plugin Build System
#
# Targets:
#   make build              - Package the plugin (unsigned)
#   make dev                - Build + SWIMS dev sign
#   make rel                - Build + SWIMS release sign
#   make sign-local         - Build + sign with a local PEM key (offline testing)
#   make clean              - Remove build artifacts
#   make setup              - Clone build repo (one-time)
#
# SWIMS signing prerequisites:
#   1. Run 'make setup' once to clone the build repo
#   2. Place SWIMS tokens in the SWIMS_TICKET_DIR:
#        .sec_id_new              Vault role/secret IDs
#        ACI_NEW_SWIMS_DEV.token  SWIMS build auth token (dev)
#      Copy from a recent build sandbox (e.g. *-build/tools/code_sign/)
#   3. Run: make dev CODE_SIGN_CREDENTIALS=user:token
#
# Uses PROJECT=aci (ACI SWIMS key identity) so that the resulting
# signature verifies against the AbraxasACIDev.pem public key that
# ships on every ND box at /certs/signing/dev.pem.
#
# Signing produces a NAP-style JSON signature file (manifest.yaml.signature)
# verified by imagesign.VerifyAppSignature / verifyPKI (SHA-256, PKCS#1 v1.5).
# SWIMS targets use tsign (not bsign); local target produces the same JSON.
#
# For local testing without SWIMS:
#   make sign-local LOCAL_KEY=keys/dev.pem

PLUGIN_DIR  ?= pre-upgrade-validation
OUT_DIR     ?= dist
STAGING     := .staging

# Build environment — cloned from nd-org-git/build, same as release repo
BUILD_ENV   := $(CURDIR)/.build-env

# SWIMS ticket directory — where .sec_id_new and ACI_NEW_SWIMS_*.token live
SWIMS_TICKET_DIR ?= $(BUILD_ENV)/swims
SWIMS_STAGING    := $(CURDIR)/.swims-staging

# Artifactory credentials for code_sign.sh (user:token), split into _usr/_psw
CODE_SIGN_CREDENTIALS ?=

# Local signing key (for make sign-local)
LOCAL_KEY   ?= keys/dev.pem

MANIFEST    := $(PLUGIN_DIR)/manifest.yaml
NAME        := $(shell grep '^name:' $(MANIFEST) | awk '{print $$2}')
VERSION     := $(shell grep '^version:' $(MANIFEST) | sed 's/version: *//;s/"//g')
NDP_FILE    := $(OUT_DIR)/$(NAME)-$(VERSION).ndp

CODE_SIGN_SH := $(BUILD_ENV)/tools/code_sign.sh

.PHONY: build dev rel sign-local setup clean distclean help

help:
	@echo "NDP Plugin Build System"
	@echo ""
	@echo "  make setup             Clone build repo (one-time)"
	@echo "  make dev CODE_SIGN_CREDENTIALS=user:token"
	@echo "                         Build + SWIMS dev sign"
	@echo "  make rel CODE_SIGN_CREDENTIALS=user:token"
	@echo "                         Build + SWIMS release sign"
	@echo "  make build             Package only (no signature)"
	@echo "  make sign-local        Sign with local PEM key (offline testing)"
	@echo "  make clean             Remove build artifacts"
	@echo "  make distclean         Remove build artifacts + build env"
	@echo ""
	@echo "  PLUGIN_DIR=$(PLUGIN_DIR)  OUT_DIR=$(OUT_DIR)"

# ---- Bootstrap (one-time setup) ----

setup:
	@if [ ! -d "$(BUILD_ENV)/tools" ]; then \
		echo "Cloning build repo into $(BUILD_ENV)..."; \
		git clone --quiet --depth=1 -b main git@github.com:nd-org-git/build.git $(BUILD_ENV); \
	else \
		echo "Build env already present at $(BUILD_ENV)"; \
	fi
	@mkdir -p $(SWIMS_TICKET_DIR)
	@echo ""
	@echo "Setup complete. Place SWIMS tokens in $(SWIMS_TICKET_DIR)/:"
	@echo "  .sec_id_new              Vault role/secret IDs"
	@echo "  ACI_NEW_SWIMS_DEV.token  SWIMS build auth token (dev)"
	@echo ""
	@echo "Copy from a recent build sandbox (e.g. *-build/tools/code_sign/)."

# ---- Main targets ----

build: _stage _copy_sources _package
	@echo "Built (unsigned): $(NDP_FILE)"

dev: _check_swims _stage _copy_sources _sign_swims_dev _package
	@echo "Built (SWIMS dev-signed): $(NDP_FILE)"

rel: _check_swims _stage _copy_sources _sign_swims_rel _package
	@echo "Built (SWIMS rel-signed): $(NDP_FILE)"

sign-local: _stage _copy_sources _sign_local _package
	@echo "Built (locally signed): $(NDP_FILE)"

# ---- SWIMS signing (NAP-style JSON signature) ----
# Uses PROJECT=aci so the signature matches the ACI Abraxas public key
# baked into every ND image (/certs/signing/dev.pem == AbraxasACIDev.pem).
#
# Uses tsign (not bsign) to produce a JSON signature file compatible with
# imagesign.VerifyAppSignature / verifyPKI (SHA-256, PKCS#1 v1.5, base64).
# This is the same format used by NAP app signatures (index.json.signature).

_check_swims:
	@test -f $(CODE_SIGN_SH) || { echo "ERROR: Build env not found. Run 'make setup' first."; exit 1; }
	@test -n "$(CODE_SIGN_CREDENTIALS)" || { echo "ERROR: Set CODE_SIGN_CREDENTIALS=user:token"; exit 1; }
	@test -f $(SWIMS_TICKET_DIR)/.sec_id_new || { echo "ERROR: SWIMS tokens not found in $(SWIMS_TICKET_DIR)/"; echo "Copy .sec_id_new and ACI_NEW_SWIMS_*.token from a recent build sandbox."; exit 1; }

_sign_swims_dev:
	@echo "Signing manifest with SWIMS (dev, NAP-style tsign)..."
	@rm -rf $(SWIMS_STAGING)
	export PROJECT=aci && \
	export code_sign_artifactory_credentials_usr=$$(echo '$(CODE_SIGN_CREDENTIALS)' | cut -d: -f1) && \
	export code_sign_artifactory_credentials_psw=$$(echo '$(CODE_SIGN_CREDENTIALS)' | cut -d: -f2-) && \
	$(CODE_SIGN_SH) "$(SWIMS_STAGING)/code_sign/code_sign.x86_64" $(SWIMS_TICKET_DIR) $(SWIMS_STAGING) false main init
	export PROJECT=aci && \
	$(CODE_SIGN_SH) "$(SWIMS_STAGING)/code_sign/code_sign.x86_64" $(SWIMS_TICKET_DIR) $(SWIMS_STAGING) false main \
		tsign $(CURDIR)/$(STAGING)/manifest.yaml $(CURDIR)/$(STAGING)/manifest.yaml.signature
	@export PROJECT=aci && \
	$(CODE_SIGN_SH) "$(SWIMS_STAGING)/code_sign/code_sign.x86_64" $(SWIMS_TICKET_DIR) $(SWIMS_STAGING) false main destroy || true
	@test -f $(STAGING)/manifest.yaml.signature || { echo "ERROR: SWIMS signing failed — no signature produced"; exit 1; }
	@echo "Signed manifest with SWIMS dev key (NAP-style JSON)"

_sign_swims_rel:
	@echo "Signing manifest with SWIMS (release, NAP-style tsign)..."
	@rm -rf $(SWIMS_STAGING)
	export PROJECT=aci && \
	export code_sign_artifactory_credentials_usr=$$(echo '$(CODE_SIGN_CREDENTIALS)' | cut -d: -f1) && \
	export code_sign_artifactory_credentials_psw=$$(echo '$(CODE_SIGN_CREDENTIALS)' | cut -d: -f2-) && \
	$(CODE_SIGN_SH) "$(SWIMS_STAGING)/code_sign/code_sign.x86_64" $(SWIMS_TICKET_DIR) $(SWIMS_STAGING) true main init
	export PROJECT=aci && \
	$(CODE_SIGN_SH) "$(SWIMS_STAGING)/code_sign/code_sign.x86_64" $(SWIMS_TICKET_DIR) $(SWIMS_STAGING) true main \
		tsign $(CURDIR)/$(STAGING)/manifest.yaml $(CURDIR)/$(STAGING)/manifest.yaml.signature
	@export PROJECT=aci && \
	$(CODE_SIGN_SH) "$(SWIMS_STAGING)/code_sign/code_sign.x86_64" $(SWIMS_TICKET_DIR) $(SWIMS_STAGING) true main destroy || true
	@test -f $(STAGING)/manifest.yaml.signature || { echo "ERROR: SWIMS signing failed — no signature produced"; exit 1; }
	@echo "Signed manifest with SWIMS release key (NAP-style JSON)"

# ---- Local signing (for offline testing without SWIMS) ----
# Produces the same JSON format as tsign so verifyPKI can parse it.
# To use: generate a keypair, replace /certs/signing/dev.pem on the box
# with the public key, then sign with the private key here.

_sign_local:
	@test -f $(LOCAL_KEY) || { echo "ERROR: Local key not found at $(LOCAL_KEY)"; echo "Generate one: openssl genpkey -algorithm RSA -out $(LOCAL_KEY) -pkeyopt rsa_keygen_bits:2048"; exit 1; }
	@RAW_SIG=$$(openssl dgst -sha256 -sign $(LOCAL_KEY) $(STAGING)/manifest.yaml | base64 -w0) && \
	printf '{\n  "signatures": {\n    "dev": {\n      "created": "%s",\n      "signature": "%s"\n    }\n  }\n}\n' \
		"$$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$$RAW_SIG" > $(STAGING)/manifest.yaml.signature
	@echo "Signed manifest with local key: $(LOCAL_KEY) (NAP-style JSON)"

# ---- Internal targets ----

_stage:
	@rm -rf $(STAGING)
	@mkdir -p $(STAGING) $(OUT_DIR)

_copy_sources:
	@cp -a $(PLUGIN_DIR)/* $(STAGING)/
	@cp ../script/ND-Preupgrade-Validation.py $(STAGING)/
	@cp ../script/worker_functions.py $(STAGING)/

_package:
	@test -f $(STAGING)/manifest.yaml.signature || echo "WARNING: No signature — .ndp will fail verification on ND"
	cd $(STAGING) && tar czf ../$(NDP_FILE) .
	@rm -rf $(STAGING)
	@echo "Output: $(NDP_FILE) ($$(du -h $(NDP_FILE) | cut -f1))"

clean:
	rm -rf $(STAGING) $(OUT_DIR) $(SWIMS_STAGING)

distclean: clean
	rm -rf $(BUILD_ENV)

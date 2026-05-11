#!/usr/bin/env bash
set -euo pipefail

REPO="elicpeter/nyx"
VERSION="${NYX_VERSION:-latest}"
INSTALL_DIR="${RUNNER_TOOL_CACHE:-/tmp}/nyx"

# Optional: pin a GPG key fingerprint here (40-char, no spaces) or set
# NYX_GPG_FINGERPRINT in the calling env to require GPG-signed SHA256SUMS.
# Empty ⇒ GPG verification is skipped (SHA256 + SLSA attestation still run).
PINNED_GPG_FINGERPRINT="${NYX_GPG_FINGERPRINT:-}"

# ── Detect runner OS and architecture ─────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}-${ARCH}" in
  Linux-x86_64)        TARGET="x86_64-unknown-linux-gnu" ;;
  Linux-aarch64)       TARGET="aarch64-unknown-linux-gnu" ;;
  Darwin-x86_64)       TARGET="x86_64-apple-darwin" ;;
  Darwin-arm64)        TARGET="aarch64-apple-darwin" ;;
  *)
    echo "::error::Unsupported platform: ${OS} ${ARCH}"
    exit 1
    ;;
esac

# ── Resolve "latest" to an actual release tag ────────────────────────────────
if [[ "$VERSION" == "latest" ]]; then
  echo "::warning::version: latest follows a mutable tag. Pin to a specific release (e.g. v0.7.0) for supply-chain safety."
  API_URL="https://api.github.com/repos/${REPO}/releases/latest"
  CURL_ARGS=(-fsSL)
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    CURL_ARGS+=(-H "Authorization: token ${GITHUB_TOKEN}")
  fi
  RELEASE_JSON="$(curl "${CURL_ARGS[@]}" "$API_URL")"
  VERSION="$(echo "$RELEASE_JSON" | grep -o '"tag_name":\s*"[^"]*"' | head -1 | cut -d'"' -f4)"
  if [[ -z "$VERSION" ]]; then
    echo "::error::Failed to resolve latest release tag from ${API_URL}"
    exit 1
  fi
  echo "Resolved latest version: ${VERSION}"
fi

# ── Download the release asset into an isolated staging dir ──────────────────
ASSET_NAME="nyx-${TARGET}.zip"
RELEASE_BASE="https://github.com/${REPO}/releases/download/${VERSION}"
DOWNLOAD_URL="${RELEASE_BASE}/${ASSET_NAME}"
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

CURL_COMMON=(-fsSL)
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  CURL_COMMON+=(-H "Authorization: token ${GITHUB_TOKEN}")
fi

echo "Downloading nyx ${VERSION} for ${TARGET}..."
curl "${CURL_COMMON[@]}" -o "${STAGING}/${ASSET_NAME}" "$DOWNLOAD_URL"

# SHA256SUMS is required — the whole release signing chain hinges on it.
echo "Downloading SHA256SUMS..."
curl "${CURL_COMMON[@]}" -o "${STAGING}/SHA256SUMS" "${RELEASE_BASE}/SHA256SUMS"

# SHA256SUMS.asc is optional (GPG signing was wired up mid-0.x); fetch it if
# present so we can attempt signature verification.
SIG_PATH=""
if curl "${CURL_COMMON[@]}" -o "${STAGING}/SHA256SUMS.asc" "${RELEASE_BASE}/SHA256SUMS.asc" 2>/dev/null; then
  SIG_PATH="${STAGING}/SHA256SUMS.asc"
fi

# ── Mandatory: verify the binary's SHA256 matches SHA256SUMS ─────────────────
(
  cd "$STAGING"
  # --ignore-missing: SHA256SUMS lists every platform archive; we only have one.
  if ! sha256sum --ignore-missing -c SHA256SUMS >/dev/null 2>&1; then
    echo "::error::SHA256 verification failed for ${ASSET_NAME}. Release may be tampered."
    echo "Expected (from SHA256SUMS):"
    grep -F "${ASSET_NAME}" SHA256SUMS || true
    echo "Actual:"
    sha256sum "${ASSET_NAME}" || true
    exit 1
  fi
)
echo "::notice::SHA256 checksum verified for ${ASSET_NAME}."

# ── Best-effort: GPG verify SHA256SUMS.asc against a pinned fingerprint ──────
# Trust model: only accept a signature from a fingerprint we have pinned. A
# signature from any other key is treated as a failure, not a success. If no
# fingerprint is pinned, GPG verification is skipped (SHA256+SLSA still run).
if [[ -n "$SIG_PATH" ]]; then
  if [[ -z "$PINNED_GPG_FINGERPRINT" ]]; then
    echo "::warning::SHA256SUMS.asc found but no GPG fingerprint pinned. Set NYX_GPG_FINGERPRINT (40-char, no spaces) to enforce GPG verification."
  elif ! command -v gpg >/dev/null 2>&1; then
    echo "::warning::gpg not installed on runner; skipping SHA256SUMS.asc verification."
  else
    # Fetch the pinned key from keys.openpgp.org into an ephemeral keyring.
    GNUPGHOME="$(mktemp -d)"
    export GNUPGHOME
    chmod 700 "$GNUPGHOME"
    trap 'rm -rf "$STAGING" "$GNUPGHOME"' EXIT
    if ! gpg --batch --keyserver hkps://keys.openpgp.org \
            --recv-keys "$PINNED_GPG_FINGERPRINT" >/dev/null 2>&1; then
      echo "::error::Failed to fetch GPG key ${PINNED_GPG_FINGERPRINT} from keys.openpgp.org."
      exit 1
    fi
    # --status-fd 1 gives machine-readable output; VALIDSIG + the pinned fpr
    # is the only accept condition.
    GPG_STATUS="$(gpg --batch --status-fd 1 --verify \
                      "$SIG_PATH" "${STAGING}/SHA256SUMS" 2>/dev/null || true)"
    if ! grep -q "^\[GNUPG:\] VALIDSIG ${PINNED_GPG_FINGERPRINT} " <<<"$GPG_STATUS"; then
      echo "::error::GPG signature on SHA256SUMS does not match pinned fingerprint ${PINNED_GPG_FINGERPRINT}."
      echo "$GPG_STATUS"
      exit 1
    fi
    echo "::notice::GPG signature verified against ${PINNED_GPG_FINGERPRINT}."
  fi
else
  echo "::warning::SHA256SUMS.asc not published for ${VERSION}; relying on SHA256 + SLSA only."
fi

# ── Best-effort: SLSA build-provenance attestation (Sigstore) ────────────────
# gh attestation verify ships with the gh CLI (preinstalled on GH-hosted
# runners) and validates attestations produced by actions/attest-build-
# provenance against the Sigstore public-good transparency log. Unlike GPG
# this requires no pre-shared key and is the preferred trust root.
if command -v gh >/dev/null 2>&1; then
  if gh attestation verify "${STAGING}/${ASSET_NAME}" --repo "${REPO}" >/dev/null 2>&1; then
    echo "::notice::SLSA build provenance verified for ${ASSET_NAME}."
  else
    echo "::warning::gh attestation verify failed or no attestation present for ${VERSION}. (Expected for releases predating attest-build-provenance.)"
  fi
else
  echo "::warning::gh CLI not available; skipping SLSA attestation verification."
fi

# ── Extract and install ──────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
# The zip stores target/{TARGET}/release/nyx — use -j to flatten paths
unzip -o -j "${STAGING}/${ASSET_NAME}" "*/nyx" -d "$INSTALL_DIR"
chmod +x "${INSTALL_DIR}/nyx"

# ── Add to PATH for subsequent steps ─────────────────────────────────────────
echo "${INSTALL_DIR}" >> "$GITHUB_PATH"

# ── Verify and set output ────────────────────────────────────────────────────
INSTALLED_VERSION="$("${INSTALL_DIR}/nyx" --version 2>&1 | head -1 || echo "unknown")"
echo "nyx-version=${INSTALLED_VERSION}" >> "$GITHUB_OUTPUT"
echo "Installed nyx: ${INSTALLED_VERSION} (${TARGET})"

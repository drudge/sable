#!/usr/bin/env bash
set -Eeuo pipefail

readonly SABLE_REPOSITORY="${SABLE_REPOSITORY:-drudge/sable}"
readonly SABLE_RELEASE_BASE="https://github.com/${SABLE_REPOSITORY}/releases"
INSTALL_TEMPORARY_DIRECTORY=""

cleanup() {
  if [[ -n "${INSTALL_TEMPORARY_DIRECTORY}" ]]; then
    rm -rf -- "${INSTALL_TEMPORARY_DIRECTORY}"
  fi
}

fail() {
  printf 'sable installer: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

release_tag() {
  if [[ -n "${SABLE_VERSION:-}" ]]; then
    if [[ "${SABLE_VERSION}" == v* ]]; then
      printf '%s\n' "${SABLE_VERSION}"
    else
      printf 'v%s\n' "${SABLE_VERSION}"
    fi
    return
  fi
  local effective_url
  effective_url="$(curl -fsSIL -o /dev/null -w '%{url_effective}' "${SABLE_RELEASE_BASE}/latest")" || \
    fail "could not determine the latest Sable release"
  [[ "${effective_url}" == */tag/* ]] || fail "latest release URL is invalid: ${effective_url}"
  printf '%s\n' "${effective_url##*/tag/}"
}

release_architecture() {
  case "$(uname -m)" in
    x86_64 | amd64) printf 'amd64\n' ;;
    aarch64 | arm64) printf 'arm64\n' ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
  esac
}

verify_archive() {
  local checksums_path="$1"
  local archive_path="$2"
  local archive_name
  archive_name="$(basename "${archive_path}")"
  local expected
  expected="$(awk -v file="${archive_name}" '$2 == file { print $1 }' "${checksums_path}")"
  [[ -n "${expected}" ]] || fail "${archive_name} is missing from checksums.txt"
  local actual
  actual="$(sha256sum "${archive_path}" | awk '{ print $1 }')"
  [[ "${actual}" == "${expected}" ]] || fail "checksum verification failed for ${archive_name}"
}

main() {
  [[ "$(uname -s)" == "Linux" ]] || fail "this installer supports Linux only"
  [[ "${EUID}" -eq 0 ]] || fail "run this installer as root"
  require_command curl
  require_command tar
  require_command sha256sum
  require_command systemctl

  local tag version architecture archive_name archive_path
  tag="$(release_tag)"
  version="${tag#v}"
  architecture="$(release_architecture)"
  archive_name="sable_${version}_linux_${architecture}.tar.gz"
  INSTALL_TEMPORARY_DIRECTORY="$(mktemp -d)"
  trap cleanup EXIT
  archive_path="${INSTALL_TEMPORARY_DIRECTORY}/${archive_name}"

  printf 'Downloading Sable %s for linux/%s...\n' "${version}" "${architecture}"
  curl -fsSL "${SABLE_RELEASE_BASE}/download/${tag}/${archive_name}" -o "${archive_path}"
  curl -fsSL "${SABLE_RELEASE_BASE}/download/${tag}/checksums.txt" -o "${INSTALL_TEMPORARY_DIRECTORY}/checksums.txt"
  verify_archive "${INSTALL_TEMPORARY_DIRECTORY}/checksums.txt" "${archive_path}"
  tar -xzf "${archive_path}" -C "${INSTALL_TEMPORARY_DIRECTORY}"

  local executable="${INSTALL_TEMPORARY_DIRECTORY}/sable_${version}_linux_${architecture}/sable"
  [[ -x "${executable}" ]] || fail "release archive does not contain the Sable executable"
  "${executable}" install "$@"
}

main "$@"

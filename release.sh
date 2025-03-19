#!/bin/bash
# Script to update and upload package to PyPI.
#
# This script performs the following steps:
# 1. Validates that required commands are available.
# 2. Optionally bumps the project version if the --bump flag is provided.
# 3. Builds source and wheel distributions.
# 4. Uploads the distributions to a specified PyPI repository.
# 5. Cleans up temporary build artifacts.
#
# Usage:
#   ./release.sh [--bump version_part]
#
#   --bump version_part    Bump version using bump2version (patch, minor, or major)

set -euo pipefail

###############################################################################
# usage
#
# Prints the usage instructions and exits.
#
# Returns:
#   None
###############################################################################
usage() {
    echo "Usage: $0 [--bump version_part]"
    echo "  --bump version_part    Bump version using bump2version (patch, minor, or major)"
    exit 1
}

###############################################################################
# error_exit
#
# Prints an error message to stderr and exits.
#
# Parameters:
#   error_msg : Error message to display.
#
# Returns:
#   None
###############################################################################
error_exit() {
    echo "Error: $1" >&2
    exit 1
}

# Check required commands: python3 and twine.
for cmd in python3 twine; do
    command -v "$cmd" >/dev/null 2>&1 || error_exit "$cmd is not installed."
done

# Optionally, handle version bump flag.
bump_flag="no"
if [[ "${1-}" == "--bump" ]]; then
    if ! command -v bump2version >/dev/null 2>&1; then
        error_exit "bump2version is not installed. Cannot bump version."
    fi
    if [[ -z "${2-}" ]]; then
        usage
    fi
    bump_part="$2"
    bump_flag="yes"
    shift 2
fi

if [[ "$#" -gt 0 ]]; then
    usage
fi

# Remove previous builds
echo "Cleaning up previous builds..."
rm -rf dist build *.egg-info

# Bump version if requested
if [[ "$bump_flag" == "yes" ]]; then
    echo "Bumping version ($bump_part)..."
    echo "Retrieving current version from version file..."
    current_version=$(cat version)
    bump2version --current-version "$current_version" "$bump_part" setup.py version
fi

# Create source distribution and wheel
echo "Building source and wheel distributions..."
python3 setup.py sdist bdist_wheel

# Upload the package to PyPI
REPO="flask-lac"
echo "Uploading distributions to PyPI repository: $REPO ..."
twine upload dist/* --repository "$REPO"

# Clean up build artifacts
echo "Cleaning up build artifacts..."
rm -rf dist build *.egg-info

echo "Package updated and uploaded successfully."
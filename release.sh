#!/bin/bash

# Script to update and upload package to PyPI

# Exit immediately if a command exits with a non-zero status
set -e

# Remove previous builds
rm -rf dist

# Bump version (assuming you are using bump2version)

# Create source distribution and wheel
python3 setup.py sdist bdist_wheel

# Upload the package to PyPI
#twine upload dist/*

# Clean up
#rm -rf dist build *.egg-info

echo "Package updated and uploaded successfully."
#!/bin/bash

# Script to upload package to PyPI

# Exit immediately if a command exits with a non-zero status
set -e

# Remove previous builds
rm -rf dist

# Create source distribution and wheel
python3 setup.py sdist bdist_wheel

# Upload the package to PyPI
twine upload dist/*

# Clean up
rm -rf dist build *.egg-info

echo "Package uploaded successfully."
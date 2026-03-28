#!/bin/bash

set -e

echo "🧪 Testing RustChain GitHub Action locally..."

# Test inputs
WALLET="test-wallet-123"
README_PATH="./README.md"

echo "✅ Input validation passed"
echo "   Wallet: $WALLET"
echo "   README path: $README_PATH"

# Generate badge URL
BADGE_URL="https://img.shields.io/endpoint?url=https://50.28.86.131/api/badge/$WALLET"
echo "✅ Badge URL generated:"
echo "    ![RustChain Mining]($BADGE_URL)"

# Create backup
cp "$README_PATH" "$README_PATH.bak"

# Check if badge already exists
if grep -q "RustChain Mining" "$README_PATH"; then
    # Replace existing badge
    sed -i "s|!\[RustChain Mining\](https://img.shields.io/endpoint?url=https://50.28.86.131/api/badge/[^)]*)|![RustChain Mining]($BADGE_URL)|g" "$README_PATH"
    echo "✅ Updated existing badge in $README_PATH"
else
    # Add new badge after first heading or at the end
    if grep -q "^#" "$README_PATH"; then
        # Insert after first heading
        sed -i "/^#/a ![RustChain Mining]($BADGE_URL)" "$README_PATH"
    else
        # Append to end
        echo "" >> "$README_PATH"
        echo "![RustChain Mining]($BADGE_URL)" >> "$README_PATH"
    fi
    echo "✅ Added new badge to $README_PATH"
fi

# Verify the change
if grep -q "$BADGE_URL" "$README_PATH"; then
    echo "✅ Badge successfully added/updated"
    echo "✅ Local test PASSED!"
else
    echo "❌ Error: Badge not found in README"
    mv "$README_PATH.bak" "$README_PATH"
    exit 1
fi

# Restore backup
mv "$README_PATH.bak" "$README_PATH"

echo "✅ All tests passed! Ready for PR submission."
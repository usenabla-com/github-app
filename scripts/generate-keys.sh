#!/bin/bash
set -euo pipefail

# Generate cryptographic keys for Nabla GitHub App

OUTPUT_DIR="${1:-./keys}"
mkdir -p "$OUTPUT_DIR"

echo "🔐 Generating keys for Nabla GitHub App..."

# Generate webhook secret
echo "📝 Generating webhook secret..."
WEBHOOK_SECRET=$(openssl rand -hex 32)
echo "$WEBHOOK_SECRET" > "$OUTPUT_DIR/webhook-secret.txt"
echo "✅ Webhook secret saved to $OUTPUT_DIR/webhook-secret.txt"

# Generate JWT signing key for customer authentication
echo "🔑 Generating JWT signing key..."
JWT_SECRET=$(openssl rand -hex 64)
echo "$JWT_SECRET" > "$OUTPUT_DIR/jwt-secret.txt"
echo "✅ JWT secret saved to $OUTPUT_DIR/jwt-secret.txt"

# Generate Ed25519 key for attestation signing
echo "🖋️ Generating Ed25519 key for attestations..."
openssl genpkey -algorithm Ed25519 -out "$OUTPUT_DIR/attestation-private.pem"
openssl pkey -in "$OUTPUT_DIR/attestation-private.pem" -pubout -out "$OUTPUT_DIR/attestation-public.pem"
echo "✅ Attestation keys saved to $OUTPUT_DIR/attestation-*.pem"

# Create environment template
echo "📄 Creating environment template..."
cat > "$OUTPUT_DIR/.env.template" << EOF
# Nabla GitHub App Environment Variables

# Database
DATABASE_URL=postgresql://username:password@localhost/nabla

# GitHub App Configuration
GITHUB_APP_ID=your_github_app_id
GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
your_github_app_private_key_here
-----END RSA PRIVATE KEY-----"
GITHUB_API_BASE=https://api.github.com
GITHUB_WEBHOOK_SECRET=$WEBHOOK_SECRET

# Stripe Configuration
STRIPE_WEBHOOK_SECRET=whsec_your_stripe_webhook_secret

# JWT Configuration
JWT_SECRET=$JWT_SECRET

# Server Configuration
PORT=8080
RUST_LOG=info
EOF

echo "✅ Environment template saved to $OUTPUT_DIR/.env.template"

# Set secure permissions
chmod 600 "$OUTPUT_DIR"/*.txt
chmod 600 "$OUTPUT_DIR"/*.pem
chmod 644 "$OUTPUT_DIR/.env.template"

echo ""
echo "🎉 Key generation complete!"
echo ""
echo "📋 Next steps:"
echo "1. Copy .env.template to .env and fill in your GitHub App details"
echo "2. Use the webhook secret when configuring your GitHub App"
echo "3. Keep all generated keys secure and never commit them to version control"
echo "4. For production, store secrets in a secure key management system"
echo ""
echo "⚠️  Important: Add $OUTPUT_DIR/ to your .gitignore file"
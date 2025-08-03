#!/bin/bash
set -euo pipefail

# Nabla GitHub App Deployment Script

# Configuration
APP_NAME="${APP_NAME:-nabla-github-app}"
ENVIRONMENT="${ENVIRONMENT:-production}"
DATABASE_URL="${DATABASE_URL:-}"
GITHUB_APP_ID="${GITHUB_APP_ID:-}"
GITHUB_PRIVATE_KEY="${GITHUB_PRIVATE_KEY:-}"
GITHUB_WEBHOOK_SECRET="${GITHUB_WEBHOOK_SECRET:-}"
STRIPE_WEBHOOK_SECRET="${STRIPE_WEBHOOK_SECRET:-}"
GITHUB_API_BASE="${GITHUB_API_BASE:-https://api.github.com}"

echo "🚀 Deploying Nabla GitHub App to $ENVIRONMENT"

# Validate required environment variables
if [ -z "$DATABASE_URL" ]; then
    echo "❌ DATABASE_URL is required"
    exit 1
fi

if [ -z "$GITHUB_APP_ID" ]; then
    echo "❌ GITHUB_APP_ID is required"
    exit 1
fi

if [ -z "$GITHUB_PRIVATE_KEY" ]; then
    echo "❌ GITHUB_PRIVATE_KEY is required"
    exit 1
fi

if [ -z "$GITHUB_WEBHOOK_SECRET" ]; then
    echo "❌ GITHUB_WEBHOOK_SECRET is required"
    exit 1
fi

if [ -z "$STRIPE_WEBHOOK_SECRET" ]; then
    echo "❌ STRIPE_WEBHOOK_SECRET is required"
    exit 1
fi

# Build the application
echo "🔨 Building application..."
cargo build --release --bin server

# Run database migrations
echo "🗄️ Setting up database..."
if command -v psql &> /dev/null; then
    psql "$DATABASE_URL" -f scripts/setup-db.sql
else
    echo "⚠️ psql not found, skipping database setup"
    echo "   Please run scripts/setup-db.sql manually"
fi

# Create systemd service file for Linux deployment
if [ "$ENVIRONMENT" = "production" ] && [ -d "/etc/systemd/system" ]; then
    echo "📝 Creating systemd service..."
    
    cat > /tmp/${APP_NAME}.service << EOF
[Unit]
Description=Nabla GitHub App
After=network.target

[Service]
Type=simple
User=nabla
Group=nabla
WorkingDirectory=/opt/nabla
ExecStart=/opt/nabla/target/release/server
Restart=always
RestartSec=5

Environment=DATABASE_URL=$DATABASE_URL
Environment=GITHUB_APP_ID=$GITHUB_APP_ID
Environment=GITHUB_PRIVATE_KEY="$GITHUB_PRIVATE_KEY"
Environment=GITHUB_WEBHOOK_SECRET=$GITHUB_WEBHOOK_SECRET
Environment=STRIPE_WEBHOOK_SECRET=$STRIPE_WEBHOOK_SECRET
Environment=GITHUB_API_BASE=$GITHUB_API_BASE
Environment=PORT=8080
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

    sudo mv /tmp/${APP_NAME}.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable ${APP_NAME}
    
    echo "✅ Systemd service created"
fi

# Docker deployment option
if command -v docker &> /dev/null && [ -f "Dockerfile" ]; then
    echo "🐳 Building Docker image..."
    docker build -t ${APP_NAME}:latest .
    
    if [ "$ENVIRONMENT" = "production" ]; then
        echo "🚀 Starting Docker container..."
        docker run -d \
            --name ${APP_NAME} \
            --restart unless-stopped \
            -p 8080:8080 \
            -e DATABASE_URL="$DATABASE_URL" \
            -e GITHUB_APP_ID="$GITHUB_APP_ID" \
            -e GITHUB_PRIVATE_KEY="$GITHUB_PRIVATE_KEY" \
            -e GITHUB_WEBHOOK_SECRET="$GITHUB_WEBHOOK_SECRET" \
            -e STRIPE_WEBHOOK_SECRET="$STRIPE_WEBHOOK_SECRET" \
            -e GITHUB_API_BASE="$GITHUB_API_BASE" \
            -e PORT=8080 \
            -e RUST_LOG=info \
            ${APP_NAME}:latest
    fi
fi

echo "✅ Deployment complete!"
echo ""
echo "Next steps:"
echo "1. Configure your GitHub App webhook URL to point to your server"
echo "2. Configure Stripe webhooks to point to /webhooks/stripe"
echo "3. Monitor logs for any issues"
echo ""
echo "Health check: curl http://localhost:8080/health"
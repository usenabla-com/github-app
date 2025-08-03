# Nabla GitHub App

A Rust-based GitHub App for automated firmware security scanning and attestation generation, supporting both GitHub.com and GitHub Enterprise Server (GHES).

## Architecture

```
nabla-github-app/
├── crates/
│   ├── core/              # Shared types: BuildResult, ScanConfiguration, etc.
│   ├── runner/            # Build detection + execution logic
│   ├── scanner/           # Binary analysis (SBOM, CVE scan, etc.)
│   ├── attestation/       # In-toto statement + sigstore
│   ├── github/            # Webhook receiver, Octocrab client, PR commenting
│   └── auth/              # Database-based plan validation + tier enforcement
├── api/                   # Axum app: webhook endpoint + metrics + health
├── action/                # GitHub Action CLI entrypoint
├── scripts/               # Deployment, DB setup, secret generation
├── Cargo.toml             # Workspace root
└── README.md
```

## Features

- **Multi-Platform Support**: GitHub.com and GitHub Enterprise Server (GHES)
- **Build System Detection**: Cargo, Makefile, CMake, PlatformIO, Zephyr West, STM32CubeIDE, SCons
- **Binary Security Scanning**: Using the `nabla-cli` crate for analysis
- **Reachability Analysis**: Vulnerability exploitability assessment
- **Attestation Generation**: In-toto compliant security attestations
- **Subscription Management**: Stripe-based billing with database-driven feature gating
- **GitHub Action**: Standalone CLI for CI/CD integration
- **SARIF Output**: Industry-standard security report format

## Quick Start

### 1. Generate Keys and Secrets

```bash
./scripts/generate-keys.sh ./keys
```

### 2. Setup Database

```bash
# Create PostgreSQL database
createdb nabla

# Run setup script
psql nabla -f scripts/setup-db.sql
```

### 3. Configure Environment

```bash
# Copy template and fill in your values
cp keys/.env.template .env
# Edit .env with your GitHub App credentials
```

### 4. Build and Run

```bash
# Build all components
cargo build --release

# Run the API server
cargo run --bin server

# Or use the GitHub Action CLI
cargo run --bin nabla-action -- scan --path ./firmware-project
```

## GitHub App Setup

1. **Create GitHub App**: Go to GitHub Settings > Developer settings > GitHub Apps
2. **Configure Permissions**:
   - Repository permissions: Contents (read), Metadata (read), Pull requests (write), Checks (write)
   - Webhook URL: `https://your-domain.com/webhooks/github`
   - Webhook secret: Use the generated webhook secret
3. **Subscribe to Events**: Push, Pull request, Installation
4. **Install the App**: Install on target repositories/organizations

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `GITHUB_APP_ID` | GitHub App ID | Yes |
| `GITHUB_PRIVATE_KEY` | GitHub App private key (PEM) | Yes |
| `GITHUB_WEBHOOK_SECRET` | Webhook signature secret | Yes |
| `GITHUB_API_BASE` | GitHub API base URL | No (defaults to github.com) |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signature secret | Yes |
| `PORT` | Server port | No (defaults to 3000) |

## GHES Support

For GitHub Enterprise Server deployments:

```bash
export GITHUB_API_BASE="https://your-ghes.company.com/api/v3"
export GITHUB_APP_ID="your_ghes_app_id"
# ... other environment variables
```

The same codebase supports multiple GitHub instances by configuring different app records in the database.

## Database Schema

- **customers**: Customer information and billing events
- **github_apps**: GitHub App configurations (supports multiple instances)
- **github_installations**: Installation tracking per app

## GitHub Action Usage

```yaml
name: Nabla Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan firmware
        run: |
          ./nabla-action scan \
            --path . \
            --severity medium \
            --output sarif \
            --file security-results.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: security-results.sarif
```

## API Endpoints

- `GET /health` - Health check
- `POST /webhooks/github` - GitHub webhook receiver
- `POST /webhooks/stripe` - Stripe webhook receiver
- `GET /metrics` - Prometheus metrics

## Deployment

### Docker

```bash
docker build -t nabla-github-app .
docker run -p 8080:8080 --env-file .env nabla-github-app
```

### Systemd

```bash
# Configure environment variables
sudo ./scripts/deploy.sh
sudo systemctl start nabla-github-app
```

## Development

```bash
# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run --bin server

# Format code
cargo fmt

# Lint
cargo clippy
```

## Security Considerations

- All secrets should be stored securely (e.g., HashiCorp Vault, AWS Secrets Manager)
- Database connections should use TLS
- Webhook signatures are validated for all incoming requests
- Customer data is isolated by installation ID
- Attestations are cryptographically signed

## License

[Your License Here]
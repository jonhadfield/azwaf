# azwaf

A powerful command-line tool for managing Azure Web Application Firewall (WAF) policies on Azure Front Door.

[![Go Version](https://img.shields.io/github/go-mod/go-version/jonhadfield/azwaf)](https://golang.org)
[![License](https://img.shields.io/github/license/jonhadfield/azwaf)](LICENSE)

## Overview

`azwaf` provides a comprehensive CLI for listing, inspecting, and updating Azure Front Door WAF policies. It simplifies complex WAF management tasks with features like policy backup/restore, rule copying between policies, custom rule management, and managed ruleset exclusions.

### Key Features

- **Policy Management**: List, show, copy, and delete WAF policies
- **Backup & Restore**: Save and restore complete policy configurations with metadata
- **Custom Rules**: Add, update, and delete custom rules with priority enforcement
- **Managed Rulesets**: Configure managed ruleset exclusions and settings
- **Rule Blocking**: Block IP addresses, request URIs, and user agents
- **Comparison**: Compare policies to identify configuration differences
- **Caching**: BuntDB-based caching for improved performance
- **Aliases**: Use short names instead of full Azure resource IDs

## Installation

### Prerequisites

- Go 1.24+ (for building from source)
- Azure subscription with Front Door WAF policies
- Azure credentials configured (Azure CLI, Managed Identity, or Service Principal)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/jonhadfield/azwaf.git
cd azwaf

# Build the binary
make build

# Install to system (macOS)
make mac-install

# Install to system (Linux)
make linux-install
```

The compiled binary will be available at `.local_dist/azwaf`.

### Build for Multiple Platforms

```bash
# Build for all supported platforms
make build-all

# Build for Linux only
make build-linux
```

## Configuration

### Environment Variables

- `AZURE_SUBSCRIPTION_ID` **(required)**: Azure subscription ID containing your WAF policies
- `AZWAF_LOG`: Set to `debug` for verbose logging (default: `info`)
- Standard Azure authentication variables:
  - `AZURE_CLIENT_ID`
  - `AZURE_CLIENT_SECRET`
  - `AZURE_TENANT_ID`

### Configuration File

The application looks for a configuration file at `~/.config/azwaf/config.yaml`. This file stores policy aliases for easier reference.

**Example config.yaml:**

```yaml
policy_aliases:
  prod-waf: /subscriptions/abc-123/resourceGroups/prod-rg/providers/Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/prod-policy
  staging-waf: /subscriptions/abc-123/resourceGroups/staging-rg/providers/Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/staging-policy
```

Override the config file path with `--config`:

```bash
azwaf --config /path/to/config.yaml list policies
```

## Usage

### List Policies

```bash
# List all WAF policies in the subscription
azwaf list policies

# List all Front Doors in the subscription
azwaf list frontdoors
```

### Show Policy Details

```bash
# Show policy details using full resource ID
azwaf show policy <policy-id>

# Show policy using alias (from config file)
azwaf show policy prod-waf

# Show policy in JSON format
azwaf show policy prod-waf --format json
```

### Backup & Restore

```bash
# Backup a policy to file
azwaf backup policy prod-waf --output prod-waf-backup.json

# Restore a policy from backup
azwaf restore policy --input prod-waf-backup.json

# Restore to a different policy
azwaf restore policy --input backup.json --target staging-waf
```

### Copy Policies

```bash
# Copy entire policy from source to destination
azwaf copy policy --source prod-waf --destination staging-waf

# Copy only custom rules
azwaf copy policy --source prod-waf --destination staging-waf --custom-rules-only

# Copy only managed rulesets
azwaf copy policy --source prod-waf --destination staging-waf --managed-rules-only
```

### Custom Rules Management

Custom rules are automatically assigned priorities based on their action type:
- **Log rules**: 1000-1999
- **Allow rules**: 3000-3999
- **Block rules**: 5000-5999

```bash
# Add a custom rule to block an IP address
azwaf add custom-rule prod-waf \
  --name "BlockMaliciousIP" \
  --action Block \
  --rule-type MatchRule \
  --match-variable RemoteAddr \
  --operator IPMatch \
  --match-values "192.168.1.100,10.0.0.50"

# Add a rate limit rule
azwaf add custom-rule prod-waf \
  --name "RateLimit" \
  --action Block \
  --rule-type RateLimitRule \
  --rate-limit-threshold 100 \
  --rate-limit-duration-minutes 1

# Delete a custom rule
azwaf delete custom-rule prod-waf --name "BlockMaliciousIP"
```

### Managed Ruleset Exclusions

```bash
# Add exclusions to a managed ruleset
azwaf add exclusions prod-waf \
  --ruleset-type "Microsoft_DefaultRuleSet" \
  --ruleset-version "2.1" \
  --match-variable "RequestHeaderNames" \
  --selector "User-Agent" \
  --operator "Equals"

# Delete managed ruleset exclusions
azwaf delete managed-exclusion prod-waf \
  --ruleset-type "Microsoft_DefaultRuleSet" \
  --ruleset-version "2.1"
```

### Block Rules

Quick commands to block specific patterns:

```bash
# Block IP addresses
azwaf add block prod-waf --ip "192.168.1.100,10.0.0.50"

# Block request URIs
azwaf add block prod-waf --uri "/admin,/wp-admin"

# Block user agents
azwaf add block prod-waf --user-agent "BadBot,MaliciousScanner"
```

### Compare Policies

```bash
# Compare two policies and show differences
azwaf compare --source prod-waf --destination staging-waf

# Output comparison in JSON format
azwaf compare --source prod-waf --destination staging-waf --format json
```

### Delete Policy

```bash
# Delete a WAF policy (with confirmation prompt)
azwaf delete policy prod-waf

# Force delete without confirmation
azwaf delete policy prod-waf --force
```

## Architecture

### Project Structure

```
azwaf/
├── cmd/
│   ├── azwaf/           # Main entry point
│   └── commands/        # CLI command implementations
├── policy/              # Core WAF policy logic
│   ├── policy.go        # Main types and interfaces
│   ├── custom_rules.go  # Custom rule management
│   ├── policy_managed.go # Managed ruleset operations
│   ├── backup.go        # Backup functionality
│   ├── restore.go       # Restore functionality
│   ├── data.go          # Data structures and marshaling
│   └── output.go        # CLI output formatting
├── session/             # Azure authentication and client management
│   ├── session.go       # Session handling
│   ├── clients.go       # Azure SDK client initialization
│   └── config.go        # Session configuration
├── config/              # Application configuration
│   ├── config.go        # Config file parsing
│   └── constants.go     # Application-wide constants
├── cache/               # BuntDB caching for API responses
└── helpers/             # Shared utility functions
```

### Key Design Patterns

1. **Session-based Architecture**: All Azure operations go through a centralized session that manages authentication and caching
2. **Policy Wrapper Pattern**: Policies are wrapped with metadata (`WrappedPolicy`) for backup/restore operations
3. **Resource ID Abstraction**: Uses aliases from config file to map short names to full Azure resource IDs
4. **Custom Rule Priorities**: Enforces ordering to ensure proper rule evaluation

### Important Limits

- Max custom rules per policy: 90
- Max IP match values per rule: 600
- Max policies to fetch: 200
- Max Front Doors to fetch: 100

## Development

### Running Tests

```bash
# Run unit tests with coverage
make test

# Run integration tests (requires Azure credentials)
make test.integration

# Generate and view coverage report
make coverage

# Run a specific test
go test -v ./policy -run TestSpecificFunction
```

### Code Quality

```bash
# Format code
make fmt

# Run linter
make lint

# Run security analysis
make gosec

# Run code critic
make critic

# Run all checks (pre-commit)
make ci
```

### Testing Approach

- **Unit tests**: Use mocked Azure clients for fast, isolated testing
- **Integration tests**: Require real Azure credentials, gated with build tags
- **Test data**: Sample policies and IP lists in `policy/testdata/`

## Authentication

`azwaf` supports standard Azure authentication methods:

1. **Azure CLI**: Run `az login` before using azwaf
2. **Managed Identity**: Automatically detected when running on Azure resources
3. **Service Principal**: Set `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, and `AZURE_TENANT_ID`
4. **Environment Variables**: Standard Azure SDK environment variables

## Troubleshooting

### Enable Debug Logging

```bash
export AZWAF_LOG=debug
azwaf list policies
```

### Common Issues

**Authentication Errors**
- Ensure `AZURE_SUBSCRIPTION_ID` is set
- Verify Azure credentials are configured (`az login` or environment variables)
- Check subscription access permissions

**Policy Not Found**
- Verify the policy exists: `azwaf list policies`
- Check alias configuration in `~/.config/azwaf/config.yaml`
- Use full resource ID instead of alias

**Rate Limiting**
- The tool implements caching to reduce API calls
- Clear cache if stale: Remove `~/.cache/azwaf/` directory

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow Go best practices and idioms
- Add unit tests for new functionality
- Update documentation for user-facing changes
- Run `make ci` before committing to ensure code quality

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For issues, questions, or feature requests, please [open an issue](https://github.com/jonhadfield/azwaf/issues) on GitHub.

## Acknowledgments

Built with:
- [Azure SDK for Go](https://github.com/Azure/azure-sdk-for-go)
- [urfave/cli](https://github.com/urfave/cli) for CLI framework
- [BuntDB](https://github.com/tidwall/buntdb) for caching
- [logrus](https://github.com/sirupsen/logrus) for logging

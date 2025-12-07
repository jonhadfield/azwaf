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

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Configuration](#configuration)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Architecture](#architecture)
- [Development](#development)
- [Authentication](#authentication)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

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

## Quick Start

```bash
# Set required environment variable
export AZURE_SUBSCRIPTION_ID="your-subscription-id"

# List all WAF policies
azwaf list policies

# Show detailed policy information
azwaf show policy <policy-id>
```

## Usage

### List Resources

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

`azwaf` automatically assigns rule priorities based on action type to ensure proper evaluation order:

| Action | Priority Range | Purpose |
|--------|----------------|---------|
| Log | 1000-1999 | Observability without blocking |
| Allow | 3000-3999 | Explicit permits (bypass blocks) |
| Block | 5000-5999 | Security enforcement |

**Priority Assignment**: Rules are automatically assigned the next available priority in their range. Lower numbers evaluate first.

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
azwaf add exclusion prod-waf \
  --rule-set "Microsoft_DefaultRuleSet" \
  --match-variable "RequestHeaderNames" \
  --selector "User-Agent" \
  --operator "Equals"

# Add exclusion to specific rule group
azwaf add exclusion prod-waf \
  --rule-group "PROTOCOL-ENFORCEMENT" \
  --match-variable "RequestCookieNames" \
  --selector "session" \
  --operator "StartsWith"

# Add exclusion to specific rule ID
azwaf add exclusion prod-waf \
  --rule-id "942100" \
  --match-variable "QueryStringArgNames" \
  --selector "search" \
  --operator "Equals"
```

### Quick Block Commands

Convenience commands to quickly block common threat patterns:

```bash
# Block specific IP addresses
azwaf add block prod-waf --ip "192.168.1.100,10.0.0.50"

# Block request URIs (paths)
azwaf add block prod-waf --uri "/admin,/wp-admin"

# Block user agents
azwaf add block prod-waf --user-agent "BadBot,MaliciousScanner"
```

**Note**: These commands create custom block rules with appropriate priorities (5000-5999 range).

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

### Azure WAF Limits

These limits are enforced by Azure Front Door WAF service:

| Resource | Limit | Notes |
|----------|-------|-------|
| Custom rules per policy | 90 | Hard limit enforced by Azure |
| IP match values per rule | 600 | Per match condition |
| Policies per fetch | 200 | Tool optimization limit |
| Front Doors per fetch | 100 | Tool optimization limit |

For more details, see [Azure Front Door limits](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-front-door-standard-and-premium-tier-service-limits).

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

### Testing Strategy

The project uses a multi-layered testing approach:

- **Unit tests**: Mocked Azure clients for fast, isolated component testing
- **Integration tests**: Real Azure credentials required, gated with build tags for optional execution
- **Test fixtures**: Sample policies and IP lists in `policy/testdata/` for reproducible testing
- **Coverage tracking**: Automated coverage reports generated via `make coverage`

## Authentication

`azwaf` supports all standard Azure SDK authentication methods, tried in the following order:

### 1. Environment Variables (Recommended for Automation)

```bash
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
```

### 2. Azure CLI (Recommended for Interactive Use)

```bash
az login
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
azwaf list policies
```

### 3. Managed Identity (For Azure Resources)

Automatically detected when running on Azure VMs, App Service, Azure Functions, etc. No additional configuration required beyond setting `AZURE_SUBSCRIPTION_ID`.

### 4. Other Methods

The tool supports additional Azure SDK authentication methods including Azure Developer CLI (`azd`), workload identity, and more. See the [Azure Identity documentation](https://learn.microsoft.com/en-us/azure/developer/go/azure-sdk-authentication) for details.

## Troubleshooting

### Enable Debug Logging

For detailed operation logs and API call tracing:

```bash
export AZWAF_LOG=debug
azwaf list policies
```

### Common Issues

#### Authentication Errors

**Symptoms**: "authentication failed" or "unauthorized" errors

**Solutions**:
- Ensure `AZURE_SUBSCRIPTION_ID` is set: `echo $AZURE_SUBSCRIPTION_ID`
- Verify Azure credentials are configured: `az account show` or check environment variables
- Confirm subscription access: `az account list --query "[].id"`
- Check required permissions: Contributor or WAF Policy Contributor role on subscription/resource group

#### Policy Not Found

**Symptoms**: "policy not found" or "resource does not exist"

**Solutions**:
- List available policies: `azwaf list policies`
- Verify alias configuration in `~/.config/azwaf/config.yaml`
- Try using full resource ID instead of alias
- Confirm policy is in the correct subscription

#### Cache Issues

**Symptoms**: Stale data or outdated policy information

**Solutions**:
- Clear cache directory: `rm -rf ~/.cache/azwaf/`
- Cache automatically expires after 15 minutes
- Use `--no-cache` flag (if available) to bypass cache

#### Performance Issues

**Symptoms**: Slow API responses or timeouts

**Solutions**:
- Enable caching to reduce API calls
- Check Azure service health: https://status.azure.com
- Reduce concurrent operations if hitting rate limits
- Use specific policy IDs instead of listing all policies

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

## Related Projects

- [Azure Front Door Documentation](https://learn.microsoft.com/en-us/azure/frontdoor/)
- [Azure WAF Documentation](https://learn.microsoft.com/en-us/azure/web-application-firewall/)
- [Azure SDK for Go](https://github.com/Azure/azure-sdk-for-go)

## Acknowledgments

Built with:
- [Azure SDK for Go](https://github.com/Azure/azure-sdk-for-go) - Azure resource management
- [urfave/cli](https://github.com/urfave/cli) - CLI framework
- [BuntDB](https://github.com/tidwall/buntdb) - Embedded key/value database for caching
- [logrus](https://github.com/sirupsen/logrus) - Structured logging
- [simpletable](https://github.com/alexeyco/simpletable) - Table formatting for output
- [jsondiff](https://github.com/wI2L/jsondiff) - JSON comparison for policy diffs

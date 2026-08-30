# azwaf

A focused command-line client for managing Azure **Front Door WAF** policies — list, inspect, copy, back up, restore, and tame managed-ruleset exclusions, all without wrestling the Azure portal. **Backup and restore** also support **Azure Application Gateway WAF** policies.

[![Latest Release](https://img.shields.io/github/v/release/jonhadfield/azwaf)](https://github.com/jonhadfield/azwaf/releases/latest)
[![Go Version](https://img.shields.io/github/go-mod/go-version/jonhadfield/azwaf)](https://golang.org)
[![License](https://img.shields.io/github/license/jonhadfield/azwaf)](LICENSE)

---

## Why azwaf?

WAF policies are notoriously fiddly to manage at scale: dozens of custom rules, sprawling managed-ruleset exclusions, no good way to diff two policies or roll one back. `azwaf` gives you a small, predictable CLI for the operations you actually do day-to-day. The bulk of the feature surface targets **Azure Front Door WAF** policies; `backup` and `restore` additionally support **Azure Application Gateway WAF** policies:

- 🔎 **Inspect** — read policies and exclusions in a tabular form a human can scan *(Front Door)*
- 📦 **Backup / restore** — snapshot policies to disk or Azure Blob Storage and restore them, in full or rule-by-rule *(Front Door **and** Application Gateway)*
- 🧬 **Copy** — clone custom rules and/or managed-ruleset config from one policy onto another, with optional diff and dry-run *(Front Door)*
- 🧹 **Surgically delete** — remove a custom rule (by name regex or priority) or a managed-rule exclusion
- 🛡️ **Add exclusions** — at rule-set, rule-group, or rule-id scope
- 🪪 **Friendly aliases** — refer to policies by short names from a config file, or by short content hashes
- 🧠 **Sanity checks** — flag *shadowed* exclusions where a wider scope already covers a narrower one

Built on the modern Azure SDK for Go, with cached lookups via [BuntDB](https://github.com/tidwall/buntdb) so repeated commands feel instant.

---

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Authentication](#authentication)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
  - [Global flags](#global-flags)
  - [`list`](#list)
  - [`show`](#show)
  - [`get`](#get)
  - [`add exclusion`](#add-exclusion)
  - [`delete`](#delete)
  - [`backup`](#backup)
  - [`restore`](#restore)
  - [`copy`](#copy)
- [Policy Aliases & Hashes](#policy-aliases--hashes)
- [Architecture](#architecture)
- [Limits](#limits)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Installation

### Prerequisites

- Go **1.27+** (only required to build from source)
- An Azure subscription with one or more Front Door or Application Gateway WAF policies
- Azure credentials available via Azure CLI, environment variables, managed identity, or another mechanism the [Azure Identity for Go](https://learn.microsoft.com/en-us/azure/developer/go/azure-sdk-authentication) chain supports

### Download a binary

Prebuilt binaries for each release are on the [latest release page](https://github.com/jonhadfield/azwaf/releases/latest). Pick the asset matching your platform:

| Platform | Asset |
| --- | --- |
| macOS (Apple Silicon) | `azwaf_darwin_arm64` |
| macOS (Intel) | `azwaf_darwin_amd64` |
| Linux x86-64 | `azwaf_linux_amd64` |
| Linux ARM64 | `azwaf_linux_arm64` |
| Linux ARM | `azwaf_linux_arm` |
| FreeBSD / NetBSD / OpenBSD x86-64 | `azwaf_freebsd_amd64`, `azwaf_netbsd_amd64`, `azwaf_openbsd_amd64` |
| Windows x86-64 | `azwaf_windows_amd64.exe` |

```bash
curl -Lo azwaf https://github.com/jonhadfield/azwaf/releases/latest/download/azwaf_darwin_arm64
chmod +x azwaf
mv azwaf /usr/local/bin/azwaf

azwaf --version
```

Prefix the `mv` with `sudo` if `/usr/local/bin` is not writable by your user — usually the case on Linux, usually not on macOS with Homebrew.

The release page shows a SHA256 digest beside each asset if you want to verify the download. The Windows binary is provisional — it cross-compiles cleanly but has not been run on Windows.

### Build from source

```bash
git clone https://github.com/jonhadfield/azwaf.git
cd azwaf

make build           # produces .local_dist/azwaf
make install         # builds and installs to /usr/local/bin (macOS and Linux)
make uninstall       # removes it again
```

`install` uses `sudo` only when the target directory needs it, so a user-local
install works without privileges:

```bash
make install PREFIX=~/.local
```

`mac-install` and `linux-install` remain as aliases for `install`.

### Cross-compile

```bash
make build-all       # darwin/amd64+arm64, linux/amd64+arm+arm64, *bsd/amd64, windows/amd64
make build-linux     # linux/amd64 only
```

---

## Configuration

### Environment variables

| Variable | Purpose |
| --- | --- |
| `AZURE_SUBSCRIPTION_ID` | Subscription containing your WAF policies. Most commands need this (or `--subscription-id`). |
| `AZWAF_LOG` | Log level: `trace`, `debug`, `info`, `warn`, or `error`. Default `info`. The `--debug` global flag is a shortcut for `debug`. When azwaf is embedded as a library it logs at `warn` and above only, to its own logger — see the `logging` package to adjust. |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | Service-principal auth (one of several supported flows). |

### Config file

`azwaf` looks for `~/.config/azwaf/config.yaml` by default. The file currently holds a single map: short aliases for full policy resource IDs.

```yaml
policy_aliases:
  prod-waf:    /subscriptions/abc-123/resourceGroups/prod-rg/providers/Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/prod-policy
  staging-waf: /subscriptions/abc-123/resourceGroups/stg-rg/providers/Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/stg-policy
```

Override the path with `--config /path/to/config.yaml`.

### Working directory

`azwaf` keeps cache and auto-backups under `~/.azwaf/`:

```
~/.azwaf/
├── cache/cache.db    # BuntDB cache for resource-id ↔ hash lookups
└── backups/          # auto-backups written before mutating commands
```

---

## Authentication

`azwaf` uses [`azidentity.NewDefaultAzureCredential`](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity), so any of the following work:

1. **Azure CLI** — `az login`, then run `azwaf` (great for interactive use)
2. **Environment variables** — set `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` (great for CI/automation)
3. **Managed identity** — when running on an Azure VM, App Service, Container App, AKS, etc.
4. **Workload identity, Azure Developer CLI (`azd`), and other SDK-supported flows**

The role assigned to your principal needs read/write on the WAF policies you intend to operate on — Front Door WAF policies, Application Gateway WAF policies, or both (`Contributor`, or a more scoped custom role).

---

## Quick Start

```bash
export AZURE_SUBSCRIPTION_ID="your-sub-id"

# Discover what's there
azwaf list policies
azwaf list frontdoors

# Inspect a policy (use the short hash printed by `list policies`, an alias, or the full resource ID)
azwaf show policy prod-waf
azwaf show policy prod-waf --custom-only --stats

# Look at managed-ruleset exclusions, including ones that shadow narrower scopes
azwaf show managed-rule-exclusions prod-waf --shadows
```

---

## Command Reference

### Global flags

These may be given **either before or after** the command name — `azwaf --subscription-id <id>
backup …` and `azwaf backup --subscription-id <id>` both work. Earlier versions accepted them
only before the command; that restriction was lifted when azwaf moved to `urfave/cli` v3.

| Flag | Aliases | Default | Description |
| --- | --- | --- | --- |
| `--subscription-id` | `-s`, `--subscription` | `$AZURE_SUBSCRIPTION_ID` | Target subscription |
| `--config` | | `~/.config/azwaf/config.yaml` | Config file path |
| `--quiet` | | `false` | Suppress non-essential output. Currently honoured by `backup` only — other commands accept the flag but still print. |
| `--debug` | | `false` | Enable debug logging, equivalent to `AZWAF_LOG=debug` |
| `--auto-backup` | | `true` | Auto-snapshot the policy to `~/.azwaf/backups/` before any mutation |

> **Careful with `-s`.** Several commands define their own `-s`, which still takes precedence
> once you are past the command name — this did not change with the position rule above. It
> means `--storage-account-id` on `backup`, `--show-diff` on `restore`, `--source` on `copy`,
> and `--match-selector` on `add exclusion` and `delete managed-rule-exclusion`. Only
> `azwaf -s <id> <command>` sets the subscription; prefer the unambiguous `--subscription-id`
> after the command name, or set `AZURE_SUBSCRIPTION_ID`.

---

### `list`

List Front Doors and policies in the subscription.

```bash
azwaf list policies                  # short hashes + names
azwaf list policies --full           # include full resource IDs
azwaf list policies --top 50         # cap results (default 200)

azwaf list frontdoors                # Front Doors and the policies they reference
```

Command aliases: `list policies` ↔ `list p`, `list frontdoors` ↔ `list f`.

Flag aliases: `--full` ↔ `-f`, `--top` ↔ `--max`.

---

### `show`

#### `show policy`

Render a policy as readable tables.

```bash
azwaf show policy prod-waf
azwaf show policy prod-waf --custom-only        # only custom rules
azwaf show policy prod-waf --managed-only       # only managed rulesets
azwaf show policy prod-waf --show-full          # show all match conditions (no truncation)
azwaf show policy prod-waf --stats              # rule counts and summary stats
azwaf show policy prod-waf --shadows            # highlight rules that shadow each other
```

#### `show managed-rule-exclusions`

Inspect exclusions across rule-set / rule-group / rule scope.

```bash
azwaf show managed-rule-exclusions prod-waf
azwaf show managed-rule-exclusions prod-waf --rule-set Microsoft_DefaultRuleSet_2.1
azwaf show managed-rule-exclusions prod-waf --rule-group SQLI
azwaf show managed-rule-exclusions prod-waf --rule-id 942100
azwaf show managed-rule-exclusions prod-waf --shadows   # exclusions made redundant by a wider scope
```

Aliases: `m`, `managed`, `exclusions`, `exclusion`.

---

### `get`

Print the raw policy payload — useful when piping into `jq`, diffing, or inspecting a specific custom rule.

```bash
azwaf get policy prod-waf | jq '.properties.customRules.rules[].name'

# Custom-rule format is "<policy>|<rule-name>"
azwaf get custom-rule "prod-waf|BlockBadActor"
azwaf get custom-rule "prod-waf|BlockBadActor" --output rule.json
```

Aliases: `get policy` ↔ `get p`, `get custom-rule` ↔ `get c`.

---

### `add exclusion`

Add a managed-rule exclusion at rule-set, rule-group, or rule-id scope. Pick **one** of `--rule-set`, `--rule-group`, `--rule-id`.

| Flag | Aliases | Required | Description |
| --- | --- | --- | --- |
| `--match-variable` | `-v`, `--variable` | yes | One of `RequestCookieNames`, `RequestHeaderNames`, `QueryStringArgNames`, `RequestBodyPostArgNames`, `RequestBodyJsonArgNames` |
| `--match-operator` | `-o`, `--operator` | yes | One of `Contains`, `EndsWith`, `Equals`, `EqualsAny`, `StartsWith` |
| `--match-selector` | `-s`, `--selector` | yes | The selector value (e.g. cookie or header name) |
| `--rule-set` | `-r` | one of three | Format: `<type>_<version>`, e.g. `Microsoft_DefaultRuleSet_2.1` |
| `--rule-group` | `-g` | one of three | E.g. `SQLI` |
| `--rule-id` | `-i` | one of three | E.g. `942100` |
| `--dry-run` | `-d` | no | Compute changes but do not push |
| `--show-diff` | | no | Print a diff between the current and proposed policy |

```bash
# Exclude the User-Agent header from a whole rule-set
azwaf add exclusion prod-waf \
  --rule-set Microsoft_DefaultRuleSet_2.1 \
  --variable RequestHeaderNames \
  --operator Equals \
  --selector User-Agent

# Exclude session cookies from a single rule, dry-run with diff
azwaf add exclusion prod-waf \
  --rule-id 942100 \
  --variable RequestCookieNames \
  --operator StartsWith \
  --selector session \
  --dry-run --show-diff
```

---

### `delete`

#### `delete custom-rule`

Delete custom rules by **name** (regex) or **priority**. At least one is required.

```bash
azwaf delete custom-rule prod-waf --name "^Block.*"        # regex match
azwaf delete custom-rule prod-waf --priority 5100
azwaf delete custom-rule prod-waf --name "Tmp_.*" --dry-run
```

Aliases: `c`, `cr`.

#### `delete managed-rule-exclusion`

Mirror of `add exclusion` — same scope and match flag *names*, same `--dry-run` / `--show-diff`.

> Unlike `add exclusion`, the scope flags here have no short aliases: spell out `--rule-set`,
> `--rule-group` and `--rule-id` in full. `-r`, `-g` and `-i` are not accepted. The match flags
> (`-v`, `-o`, `-s`) do have the same aliases as on `add exclusion`.

```bash
azwaf delete managed-rule-exclusion prod-waf \
  --rule-set Microsoft_DefaultRuleSet_2.1 \
  --variable RequestHeaderNames \
  --operator Equals \
  --selector User-Agent \
  --show-diff
```

Aliases: `m`, `mre`, `exclusion`.

---

### `backup`

Snapshot one or more policies to disk and/or Azure Blob Storage. Policy IDs (or hashes / aliases) are positional arguments. Both **Front Door** and **Application Gateway** WAF policies are supported; the resource type embedded in each resource ID determines which API the policy is fetched from. Running with no positional arguments backs up every WAF policy of either type in the subscription.

```bash
# All Front Door + Application Gateway WAF policies in the subscription
azwaf backup --path ./backups/

# Mix and match — pass full resource IDs for either type, or use FD aliases
azwaf backup prod-waf \
  /subscriptions/abc-123/resourceGroups/agw-rg/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/prod-agw \
  --path ./backups/

# Push to a Blob container (alongside or instead of local disk)
azwaf backup prod-waf \
  --container-url https://myacc.blob.core.windows.net/waf-backups

# Add a storage-account resource ID to authenticate with account keys instead
azwaf backup prod-waf \
  --container-url https://myacc.blob.core.windows.net/waf-backups \
  --storage-account-id /subscriptions/.../storageAccounts/myacc

azwaf backup prod-waf staging-waf --path ./backups/ --fail-fast
```

| Flag | Aliases | Description |
| --- | --- | --- |
| `--path` | `-p` | Local directory for backup files |
| `--container-url` | `-c` | Blob container URL to upload to. Sufficient on its own; uploads authenticate with your Azure AD identity, which needs a blob data role on the account. |
| `--storage-account-id` | `-s` | Storage-account resource ID. Optional; use with `--container-url` to authenticate with account keys rather than your Azure AD identity. Cannot be used on its own — nothing would name the container. |
| `--fail-fast` | `-f` | Stop on the first error rather than continuing |

> Mutating commands also create an auto-backup under `~/.azwaf/backups/` unless `--auto-backup=false` is set.

> Each backup file embeds a `WAFType` field (`FrontDoor` or `ApplicationGateway`) so `restore` can dispatch to the right API. Backup files produced by older versions of `azwaf` (no `WAFType` field) are treated as Front Door for backward compatibility.

---

### `restore`

Restore one or more backup files. Backup paths are positional. Both **Front Door** and **Application Gateway** WAF backups are accepted — each file's embedded `WAFType` field decides which API the restore is pushed through. You can mix backups of either type in a single invocation.

```bash
# Restore each backup, recreating the policy in its original resource group
azwaf restore ./backups/prod-waf-2026-05-04.json

# Restore custom rules only, on top of an existing target policy
azwaf restore ./backups/prod-waf-2026-05-04.json \
  --target staging-waf --custom-rules

# Restore managed-rule config only
azwaf restore ./backups/prod-waf-2026-05-04.json \
  --target staging-waf --managed-rules --show-diff

# Restore an Application Gateway WAF backup onto an existing AppGW WAF policy
azwaf restore ./backups/prod-agw-2026-05-04.json \
  --target /subscriptions/abc-123/resourceGroups/agw-rg/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/staging-agw \
  --show-diff

# Recreate into a different resource group, no prompt
azwaf restore ./backups/*.json --resource-group restored-rg --force
```

| Flag | Aliases | Description |
| --- | --- | --- |
| `--target` | `-t` | Restore on top of an existing target policy instead of recreating |
| `--resource-group` | `-r` | RG to restore new policies into (when not using `--target`) |
| `--custom-rules` | `--custom`, `-c` | Restore only custom rules |
| `--managed-rules` | `--managed`, `-m` | Restore only managed-ruleset config |
| `--show-diff` | `-s` | Show the diff before applying |
| `--dry-run` | `-d` | Compute the result but do not push |
| `--force` | | Skip the confirmation prompt |
| `--fail-fast` | `-f` | Stop on the first error |

> When `--target` is used with an Application Gateway WAF backup, the target must be a full Azure resource ID — short hashes are Front Door-only (the hash cache is populated from `list policies`, which only enumerates Front Door WAFs).

---

### `copy`

Copy custom and/or managed rules from one policy onto another. Both `--source` and `--target` are required. Hashes can be used when both policies are in the current subscription.

```bash
azwaf copy --source prod-waf --target staging-waf
azwaf copy --source prod-waf --target staging-waf --custom-rules --show-diff
azwaf copy --source prod-waf --target staging-waf --managed-rules --dry-run
azwaf copy --source prod-waf --target dr-waf --async
```

| Flag | Aliases | Description |
| --- | --- | --- |
| `--source` | `-s`, `--src` | Source policy resource ID, alias, or hash |
| `--target` | `-t` | Target policy resource ID, alias, or hash |
| `--custom-rules` | `--custom`, `-c` | Copy only custom rules |
| `--managed-rules` | `--managed`, `-m` | Copy only managed-ruleset config |
| `--show-diff` | `--show`, `--diff` | Show the diff before applying |
| `--dry-run` | `-d` | Generate the policy but do not push |
| `--async` | `-a` | Push without waiting for completion |

> Default behaviour copies **both** custom and managed rules. Use the flags above to scope it down.

---

## Policy Aliases & Hashes

You can refer to a policy in three ways:

1. **Full resource ID** — `/subscriptions/.../FrontDoorWebApplicationFirewallPolicies/prod-policy`
2. **Alias** — a short name from `~/.config/azwaf/config.yaml` (e.g. `prod-waf`)
3. **Hash** — the short string printed in `azwaf list policies`. Hashes are scoped to the current subscription, so `--subscription-id` (or `AZURE_SUBSCRIPTION_ID`) must be set when using them.

---

## Architecture

```
azwaf/
├── cmd/
│   ├── azwaf/             # main(), CLI bootstrap
│   └── commands/          # urfave/cli subcommands (add, backup, copy, …)
├── policy/                # core WAF logic
│   ├── policy.go          # types, fetch helpers, hashmap (Front Door)
│   ├── custom_rules.go    # custom-rule manipulation
│   ├── policy_managed.go  # managed-ruleset & exclusion handling
│   ├── add_exclusions.go  # add managed-rule exclusion flow
│   ├── delete_*.go        # delete custom rule / managed exclusion
│   ├── backup.go          # local + blob backups (FD + AppGW)
│   ├── restore.go         # restore flows (dispatches FD vs AppGW)
│   ├── appgw.go           # Application Gateway WAF SDK wrappers
│   ├── appgw_restore.go   # AppGW restore pipeline
│   ├── copy.go            # cross-policy copy
│   ├── compare.go         # diff helper used by --show-diff
│   ├── show.go / output.go / stats.go  # CLI rendering
│   └── frontdoor.go       # Front Door listing
├── session/               # azidentity + Azure SDK clients + cache wiring
├── config/                # config.yaml parsing, resource-ID parsing
├── cache/                 # BuntDB-backed caching (resource-id hash map, etc.)
└── helpers/               # shared utilities
```

### Design notes

- **Session is the seam.** Every Azure-touching code path runs through a `*session.Session` that owns credentials, the SDK clients, and the cache. Tests mock at this boundary.
- **Wrapped policies.** `WrappedPolicy` (Front Door) and `WrappedAppGWPolicy` (Application Gateway) decorate the SDK types with metadata (subscription, resource group, name, hashes, `WAFType`) so backup/restore/copy stay unambiguous about *which* policy a payload belongs to.
- **WAF type discrimination.** `BackupPolicies` partitions inbound resource IDs into Front Door and Application Gateway lists by inspecting the resource type segment of each ID. `RestorePolicies` peeks at every backup file's `WAFType` field and routes it to the matching restore pipeline.
- **Hash-based shorthand.** A subscription-scoped hash map (`WAFResourceIDHashMap`) lets the CLI accept short hashes in place of full resource IDs.
- **Diffing via `diff(1)`.** `--show-diff` shells out to the system `diff` for human-readable output rather than a custom JSON differ.

---

## Limits

The limits below apply to Front Door WAF policies. Application Gateway WAF policies are subject to a separate set of Azure limits — `azwaf` does not enforce or surface them.

| Resource | Limit | Source | Enforced by `azwaf`? |
| --- | --- | --- | --- |
| Custom rules per policy | **90** | Azure hard limit | Yes — every push is checked |
| IP-match values per rule | **600** | Azure hard limit | Not on the CLI paths — see note |
| Conditions per custom rule | **10** | Azure hard limit | No |
| Exclusions per scope | **100** (warns at 95) | Azure hard limit | Yes — every push is checked |
| Policies fetched per `list policies` | **200** (configurable via `--top`) | Tool default | Yes |
| Front Doors fetched per `list frontdoors` | **100** | Tool default | Yes |

> **What `azwaf` actually checks.** The custom-rule count and the per-scope exclusion count are
> both validated before every push, so `copy`, `restore` and `add exclusion` fail with a clear
> error naming the offending rule set, rule group or rule rather than letting Azure reject the
> policy — and a `--dry-run` reports it too. `show policy --stats` additionally warns from 95
> exclusions in any one scope. The remaining two limits are not enforced: the 600-IP-match check
> exists only inside the IP-network helper functions, which are exported for library use but have
> no CLI entry point, and the conditions-per-rule limit is not checked at all. Treat those two as
> upstream Azure limits you should stay within, not as guardrails the tool provides.

See [Azure Front Door service limits](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-front-door-standard-and-premium-tier-service-limits) for the Front Door upstream specifics, and [Application Gateway service limits](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#application-gateway-limits) for Application Gateway.

---

## Development

```bash
make fmt              # goimports + gofumpt
make lint             # golangci-lint
make test             # unit tests with coverage
make test.integration # integration tests (require live Azure creds)
make coverage         # opens HTML coverage report
make ci               # lint + test (run before pushing)
make gosec            # security scanner
make critic           # gocritic
```

Unit tests mock the Azure SDK clients. Integration tests sit behind build tags and need a real subscription. Test fixtures (sample policies, IP lists) live in `policy/testdata/`.

---

## Troubleshooting

**Verbose logs**

```bash
AZWAF_LOG=debug azwaf list policies
```

**“subscription-id required” / auth errors**

```bash
echo $AZURE_SUBSCRIPTION_ID         # is it set?
az account show                     # is the CLI logged in?
az account list --query "[].id"     # do you have access?
```

Make sure your principal has at least `Contributor` (or equivalent custom role) on the policies you’re touching.

**Stale or weird cached lookups**

The cache lives at `~/.azwaf/cache/cache.db` and stores resource-id ↔ hash mappings. If the contents of your subscription have changed and `azwaf` looks confused, clearing it is safe:

```bash
rm -rf ~/.azwaf/cache/
```

**Hash not found**

Hashes are scoped to a subscription. Confirm `--subscription-id` (or `AZURE_SUBSCRIPTION_ID`) matches the subscription where the policy lives, or pass the alias / full resource ID instead.

---

## Contributing

Pull requests welcome. Please:

1. Fork and create a feature branch (`git checkout -b feature/your-thing`)
2. Add tests for any new behaviour
3. Run `make ci` before pushing
4. Open a PR with a description of the change and its motivation

Issues and feature requests: <https://github.com/jonhadfield/azwaf/issues>.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Built with

- [Azure SDK for Go](https://github.com/Azure/azure-sdk-for-go) — `armfrontdoor`, `armnetwork`, `armstorage`, `azblob`, `azidentity`
- [urfave/cli](https://github.com/urfave/cli) — CLI framework
- [BuntDB](https://github.com/tidwall/buntdb) — embedded key/value cache
- standard library [log/slog](https://pkg.go.dev/log/slog) — logging (azwaf's own logger instance; silent at default level when embedded as a library)
- [simpletable](https://github.com/alexeyco/simpletable) — table rendering
- [jsondiff](https://github.com/wI2L/jsondiff) — structured JSON diffing

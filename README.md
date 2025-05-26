# azwaf

This project provides tools and helpers for working with Azure Web Application Firewall (WAF) policies.

`azwaf` exposes a command line interface for listing, inspecting and updating
Azure Front Door WAF policies. Commands include backing up policies, copying
rules between policies, adding or removing rule exclusions and more.

## Building

All modules are vendored. You can build the binary with:

```sh
make build
```

## Testing

Run unit tests with:

```sh
make test
```

Integration tests require Azure credentials and are gated behind a build tag:

```sh
make test.integration
```

## Usage

Set `AZURE_SUBSCRIPTION_ID` to the subscription that contains your policies and
run commands such as:

```sh
# list policies in the subscription
azwaf list policies

# display details of a policy
azwaf show policy <policy-id>
```

The application looks for a configuration file at
`~/.config/azwaf/config.yaml`. This file can store policy aliases which allow
shorter names to be used instead of full resource identifiers. The path can be
overridden with `--config`.

Increase verbosity by setting `AZWAF_LOG=debug`.



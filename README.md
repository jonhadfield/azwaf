# azwaf

This project provides tools and helpers for working with Azure Web Application Firewall (WAF) policies.

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



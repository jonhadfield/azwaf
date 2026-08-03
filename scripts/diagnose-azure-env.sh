#!/bin/bash

echo "=== Azure Environment Diagnostics ==="
echo ""

echo "Environment variables being checked:"
echo "AZURE_USE_MANAGED_IDENTITY: ${AZURE_USE_MANAGED_IDENTITY:-<not set>}"
echo "WEBSITE_INSTANCE_ID: ${WEBSITE_INSTANCE_ID:-<not set>}"
echo "IDENTITY_ENDPOINT: ${IDENTITY_ENDPOINT:-<not set>}"
echo "IMDS_ENDPOINT: ${IMDS_ENDPOINT:-<not set>}"
echo "MSI_ENDPOINT: ${MSI_ENDPOINT:-<not set>}"
echo "ACC_CLOUD: ${ACC_CLOUD:-<not set>}"
echo "AZURESUBSCRIPTION_CLIENT_ID: ${AZURESUBSCRIPTION_CLIENT_ID:-<not set>}"
echo "AZURE_RESOURCE_GROUP: ${AZURE_RESOURCE_GROUP:-<not set>}"
echo ""

echo "Checking for Azure VM agent:"
if [ -d "/var/lib/waagent" ]; then
    echo "✓ /var/lib/waagent exists (Azure VM detected)"
else
    echo "✗ /var/lib/waagent not found"
fi
echo ""

echo "Checking for IMDS endpoint:"
if curl -s -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" --connect-timeout 2 > /dev/null 2>&1; then
    echo "✓ IMDS endpoint is accessible (Managed Identity available)"
else
    echo "✗ IMDS endpoint not accessible"
fi
echo ""

echo "Azure CLI status:"
if command -v az &> /dev/null; then
    echo "✓ Azure CLI found at: $(which az)"
    az account show 2>&1 | head -5
else
    echo "✗ Azure CLI not found"
fi

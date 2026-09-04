# DotnetAudit Lite

[![self-test](https://github.com/Dalkory/DotnetAuditLite/actions/workflows/self-test.yml/badge.svg)](https://github.com/Dalkory/DotnetAuditLite/actions/workflows/self-test.yml)
[![release](https://img.shields.io/github/v/release/Dalkory/DotnetAuditLite)](https://github.com/Dalkory/DotnetAuditLite/releases)
[![GitHub Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-DotnetAudit%20Lite-blue?logo=github)](https://github.com/marketplace/actions/dotnetaudit-lite-preflight)

Local-first .NET repository preflight that creates readable Markdown and SARIF
2.1.0 without uploading source code to an external service.

## Install as a .NET tool

`DotnetAuditLite` 1.0.1 is published on
[NuGet.org](https://www.nuget.org/packages/DotnetAuditLite/1.0.1). Install it
globally with:

```bash
dotnet tool install --global DotnetAuditLite
dotnet-audit-lite --path .
```

To install into an isolated directory instead:

```bash
dotnet tool install DotnetAuditLite --tool-path ./.tools --version 1.0.1
./.tools/dotnet-audit-lite --path . --static-only
```

The tool runs with the current user's permissions. Review the repository and
package before installation, and use `--static-only` when the target repository
must not execute build or test commands.

## Use as a GitHub Action

Install from
[GitHub Marketplace](https://github.com/marketplace/actions/dotnetaudit-lite-preflight)
or add the Action directly:

```yaml
- uses: Dalkory/DotnetAuditLite@v1
```

![DotnetAudit Lite report preview](docs/report-preview.png)

## What it checks

- target frameworks and an embedded .NET 8/9/10 support snapshot;
- `Nullable` and warnings-as-errors settings;
- common CI, Docker, health-check and OpenTelemetry signals;
- sensitive-looking files and assignments without printing detected values;
- optional local `dotnet build`, `dotnet test` and vulnerable-package checks.

## Complete workflow

```yaml
name: .NET preflight

on:
  workflow_dispatch:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  preflight:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: Dalkory/DotnetAuditLite@v1
        with:
          path: .
          output: dotnet-preflight-report.md
          sarif-output: dotnet-preflight.sarif

      - uses: actions/upload-artifact@v4
        with:
          name: dotnet-preflight-report
          path: dotnet-preflight-report.md

      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: dotnet-preflight.sarif
          category: dotnet-audit-lite
```

The Action performs a static preflight. It writes both files but does not upload
them by itself, so teams can use only the local Markdown artifact if they do not
want Code Scanning.

## Run from source

Requirements: .NET 8 SDK or newer.

```powershell
dotnet run --project DotnetAuditLite.csproj -- `
  --path C:\path\to\repository `
  --output dotnet-preflight-report.md `
  --sarif dotnet-preflight.sarif
```

For a scan that never executes the target repository:

```powershell
dotnet run --project DotnetAuditLite.csproj -- --path C:\path\to\repository --static-only
```

The lifecycle snapshot follows the
[official Microsoft .NET support policy](https://dotnet.microsoft.com/en-us/platform/support/policy)
as of 2026-07-27. Future framework versions are marked for manual verification
instead of being guessed.

## Example result

```text
# DotnetAudit Lite — preflight report

Projects discovered: 4
Findings: 7

HIGH    net6.0: out of support
MEDIUM  No health-check wiring detected
MEDIUM  No OpenTelemetry wiring detected
LOW     Warnings are not explicitly treated as errors
```

The sample consumer repository shows the Action, downloadable Markdown artifact
and Code Scanning integration:
https://github.com/Dalkory/DotnetAuditLiteSample

## Limitations

- This is a signal-oriented pre-check, not proof of production readiness.
- Secret matching is intentionally conservative and never prints detected values.
- Static checks cannot prove runtime reliability, authorization correctness or
  regulatory compliance.
- SARIF upload works for public repositories; private repositories need the
  applicable GitHub Code Security plan and settings.
- Findings must be reviewed before sharing them outside the repository owner’s
  organization.

## Paid interpretation

Want priorities instead of a raw report? Open
[Request paid interpretation](https://github.com/Dalkory/DotnetAuditLite/issues/new?template=request-paid-interpretation.yml)
with only non-confidential context. A fixed-scope human review can turn the
preflight into a one-problem diagnosis, AI Repo Enablement, modernization
assessment or remediation plan.

Formats and contact:
https://dotnet-audit-studio.dtauskanov3.chatgpt.site/en

# ghes-secret-scanning-automation-tools
A project to enable automatic resolution and reopening of Secret Scanning alerts on GitHub Enterprise Server

**Functionality**:

* Given two Secret Scanning pattern names, new and old, resolve open new alerts that overlap with resolved old alerts while preserving the triage state of the old alert.
* Given a CSV file which specifies alerts in `owner,repo,secret_alert_number` format, reopen the specified alerts.

## Usage

### Requirements

To use this CLI you need:

* An instance of GHES.
* Administrator credentials to the instance.
* A personal access token for the administrative user with all scopes.

### Quickstart

Run `go build` to build the CLI. You can then run the CLI using the snippet below:

```bash
./ghes-secret-scanning-script create \
--url="YOUR_INSTANCE_URL" \
--pat="YOUR_ADMIN_USER_PAT"
--enterprise-name="YOUR_ENTERPRISE_NAME"
--new-pattern="YOUR_NEW_PATTERN_ID"
--old-pattern="YOUR_OLD_PATTERN_ID"
--reopen-alerts-csv-path="PATH_TO_CSV"
--dry-run="TRUE/FALSE"
```

Either an input CSV path, or new and old patterns, or all three may be specified.

Alternatively, specify your PAT via the `$GITHUB_TOKEN` env var.

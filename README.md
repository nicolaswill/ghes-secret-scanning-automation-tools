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

#### Enterprise-Wide:
```bash
./ghes-secret-scanning-script create \
--url="YOUR_INSTANCE_URL" \
--pat="YOUR_ADMIN_USER_PAT" \
--enterprise-id="YOUR_ENTERPRISE_ID" \
--new-pattern="YOUR_NEW_PATTERN_ID" \
--old-pattern="YOUR_OLD_PATTERN_ID" \
--alerts-to-reopen-csv="PATH_TO_CSV" \
--dry-run="true/false" \
--new-substring-regex="REGEX" \
--old-substring-regex="REGEX"
```

#### Organization-Wide:
Instead of specifying `--enterprise-id`, specify `--organization-ids` as a comma-delimited list of organization (e.g. `--organization-ids="org1,org2"`).

#### Repository-Wide:
Instead of specifying `--enterprise-id`, specify `--repository-ids` as a comma-delimited list of repositories in org/repo format (e.g. `--repository-ids="org1/repo1,org1/repo2,org2/repo1"`).

### Options
| Option                                              | Description                                                                                                              |
|-----------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| `--url value`                                       | The GitHub endpoint URL (default: "https://github.com/")                                                             |
| `--dry-run`                                         | Run without making changes (default: false)                                                                              |
| `--alerts-to-reopen-csv value`                      | CSV file path with alerts to reopen (owner, repo, alert number)                                                          |
| `--pat value`                                       | GitHub personal access token [$GITHUB_TOKEN]                                                                             |
| `--enterprise-id value`                             | GitHub Enterprise identifier                                                                                             |
| `--organization-ids value [ --organization-ids value ]` | Comma-delimited list of organization names                                                                               |
| `--repository-ids value [ --repository-ids value ]`     | Comma-delimited list of repository names in the format 'org/repo'                                                        |
| `--old-pattern value`                               | Old secret scanning pattern                                                                                              |
| `--new-pattern value`                               | New secret scanning pattern                                                                                              |
| `--old-substring-regex value`                       | Old secret substring regex used for correlating secret scanning alerts. WARNING: Does not support multi-line alerts.     |
| `--new-substring-regex value`                       | New secret substring regex used for correlating secret scanning alerts. WARNING: Does not support multi-line alerts.     |
| `--help, -h`                                        | show help                                                                                                                |



Either an input CSV path, both new and old patterns, or all three may be specified.

Alternatively, specify your PAT via the `$GITHUB_TOKEN` env var.

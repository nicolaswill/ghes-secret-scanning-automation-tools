package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/google/go-github/v57/github"
	"github.com/urfave/cli/v2"
	"golang.org/x/oauth2"
)

type RepoKey struct {
	Owner string
	Name  string
}

type AlertKey struct {
	Repo   RepoKey
	Number int64
}

// An alertKey and its HTML URL string
type AlertKeyAndURL struct {
	AlertKey AlertKey
	URL      string
}

// Secret scanning alert content, type, location, and path.
type AlertDetails struct {
	Secret       string
	LocationType string
	CommitSHA    string
	StartColumn  int
	EndColumn    int
	StartLine    int
	EndLine      int
	Path         string
}

// Map of repo name to alert details to alert.
type RepoKeyToAlertDetailsToAlertMap map[RepoKey]map[AlertDetails]*github.SecretScanningAlert

func makeAlertKey(alert *github.SecretScanningAlert) AlertKey {
	return AlertKey{
		Repo:   RepoKey{Owner: alert.GetRepository().GetOwner().GetLogin(), Name: alert.GetRepository().GetName()},
		Number: int64(alert.GetNumber()),
	}
}

func reopenClosedAlertsFromCSV(ctx context.Context, reopenAlertsCSVPath string, dryRun bool, client *github.Client) error {
	reopenAlertsFile, err := os.Open(reopenAlertsCSVPath)
	if err != nil {
		log.Fatalf("Error opening reopen alerts file: %s\n", err)
		return err
	}
	defer reopenAlertsFile.Close()

	reopenAlertsReader := csv.NewReader(reopenAlertsFile)
	reopenAlertsReader.FieldsPerRecord = 3
	reopenAlertsReader.Comment = '#'
	reopenAlertsReader.TrimLeadingSpace = true

	for {
		line, err := reopenAlertsReader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Fatalf("Error reading reopen alerts file: %s\n", err)
			return err
		}

		owner := line[0]
		repo := line[1]

		if owner == "" || repo == "" {
			continue
		}

		alertNumber, err := strconv.ParseInt(line[2], 10, 64)
		if err != nil {
			log.Printf("Error parsing alert number: %s\n", err)
			continue
		}

		if !dryRun {
			log.Printf("Reopening alert %d in %s/%s\n", alertNumber, owner, repo)
			opts := github.SecretScanningAlertUpdateOptions{State: "open"}
			_, _, err = client.SecretScanning.UpdateAlert(ctx, owner, repo, alertNumber, &opts)
			if err != nil {
				log.Printf("Error reopening alert: %s\n", err)
			}
		} else {
			log.Printf("Would have reopened alert %d in %s/%s\n", alertNumber, owner, repo)
		}
	}
	return nil
}

// Make a struct containing the secret scanning alert content, type, location, and path.
// While doing so, run the substring regex and adjust the startline/endline based on the location of the substring within the original Secret.
func makeAlertDetails(alert *github.SecretScanningAlert, location *github.SecretScanningAlertLocation, substringRegex *regexp.Regexp) AlertDetails {
	secret := alert.GetSecret()

	result := AlertDetails{
		Secret:       secret,
		LocationType: location.GetType(),
		CommitSHA:    location.GetDetails().GetCommitSHA(),
		StartColumn:  location.GetDetails().GetStartColumn(),
		EndColumn:    location.GetDetails().GetEndColumn(),
		StartLine:    location.GetDetails().GetStartline(),
		EndLine:      location.GetDetails().GetEndLine(),
		Path:         location.GetDetails().GetPath(),
	}

	if substringRegex != nil {
		if location.GetDetails().GetStartline() != location.GetDetails().GetEndLine() {
			log.Fatalf("Fatal: startline and endline are different for alert %s at location %s. Multiline alerts are not yet supported.\n", alert.GetHTMLURL(), location.GetDetails().GetBlobURL())
		} else {
			// get the string index of the first group of the regex
			substringIndex := substringRegex.FindStringSubmatchIndex(secret)
			if len(substringIndex) >= 4 && substringIndex[3]-substringIndex[2] > 0 {
				result.EndColumn = substringIndex[3] + result.StartColumn
				result.StartColumn += substringIndex[2]
				result.Secret = secret[substringIndex[2]:substringIndex[3]]
			}
		}
	}

	return result
}

func getSecretScanningAlertLocations(ctx context.Context, secretSubstringRegex string, alertsByRepoName map[RepoKey][]*github.SecretScanningAlert, client *github.Client, output RepoKeyToAlertDetailsToAlertMap) error {
	var wg sync.WaitGroup
	var mutex sync.RWMutex
	semaphore := make(chan struct{}, 64) // up to 64 concurrent goroutines

	// compile the substring regex if it's not empty
	var substringRegex *regexp.Regexp = nil
	if secretSubstringRegex != "" {
		substringRegex = regexp.MustCompile(secretSubstringRegex)
	}

	for repo, alerts := range alertsByRepoName {
		for _, alert := range alerts {
			wg.Add(1)
			semaphore <- struct{}{}
			go func(repo RepoKey, alert *github.SecretScanningAlert) {
				defer wg.Done()
				defer func() { <-semaphore }()
				locationOpts := github.ListOptions{PerPage: 100, Page: 1}
				for {
					locations, resp, err := client.SecretScanning.ListLocationsForAlert(ctx, repo.Owner, repo.Name, int64(alert.GetNumber()), &locationOpts)
					if err != nil {
						log.Fatalf("Error getting alert locations: %s\n", err)
						return
					}
					if len(locations) == 0 {
						log.Printf("No locations found for alert %d\n", alert.GetNumber())
					}
					for _, location := range locations {
						alertDetails := makeAlertDetails(alert, location, substringRegex)
						mutex.Lock()
						if _, ok := output[repo]; !ok {
							output[repo] = make(map[AlertDetails]*github.SecretScanningAlert)
						}
						output[repo][alertDetails] = alert
						mutex.Unlock()
					}
					if resp.NextPage == 0 {
						break
					}
					locationOpts.Page = resp.NextPage
				}
			}(repo, alert)
		}
	}

	wg.Wait()
	return nil
}

func getEnterpriseSecretScanningAlerts(ctx context.Context, client *github.Client, enterpriseName string, pattern string, opts github.SecretScanningAlertListOptions, output map[RepoKey][]*github.SecretScanningAlert) error {
	for {
		alerts, resp, err := client.SecretScanning.ListAlertsForEnterprise(ctx, enterpriseName, &opts)
		if err != nil {
			return err
		}
		for _, alert := range alerts {
			if !alert.GetRepository().GetDisabled() {
				repoKey := RepoKey{Owner: alert.GetRepository().GetOwner().GetLogin(), Name: alert.GetRepository().GetName()}
				output[repoKey] = append(output[repoKey], alert)
			}
		}
		if resp.After == "" {
			break
		}
		opts.ListCursorOptions.After = resp.After
	}
	return nil
}

func getOrganizationSecretScanningAlerts(ctx context.Context, client *github.Client, orgName string, pattern string, opts github.SecretScanningAlertListOptions, output map[RepoKey][]*github.SecretScanningAlert) error {
	for {
		alerts, resp, err := client.SecretScanning.ListAlertsForOrg(ctx, orgName, &opts)
		if err != nil {
			return err
		}
		for _, alert := range alerts {
			repoKey := RepoKey{Owner: alert.GetRepository().GetOwner().GetLogin(), Name: alert.GetRepository().GetName()}
			output[repoKey] = append(output[repoKey], alert)
		}
		if resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}
	return nil
}

func getRepositorySecretScanningAlerts(ctx context.Context, client *github.Client, repo RepoKey, pattern string, opts github.SecretScanningAlertListOptions, output map[RepoKey][]*github.SecretScanningAlert) error {
	for {
		alerts, resp, err := client.SecretScanning.ListAlertsForRepo(ctx, repo.Owner, repo.Name, &opts)
		if err != nil {
			return err
		}
		output[repo] = append(output[repo], alerts...)
		if resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}
	return nil
}

// Copy of github.SecretScanningAlertUpdateOptions with the addition of the ResolutionComment parameter
type SecretScanningAlertUpdateOptionsInternal struct {
	// State is required and sets the state of the secret scanning alert.
	// Can be either "open" or "resolved".
	// You must provide resolution when you set the state to "resolved".
	State string `json:"state"`

	// Required when the state is "resolved" and represents the reason for resolving the alert.
	// Can be one of: "false_positive", "wont_fix", "revoked", or "used_in_tests".
	Resolution *string `json:"resolution,omitempty"`

	// Optional when the state is "resolved" and represents a comment to be added to the alert.
	ResolutionComment *string `json:"resolution_comment,omitempty"`
}

// UpdateAlert updates the status of a secret scanning alert in a private repository.
//
// To use this endpoint, you must be an administrator for the repository or organization, and you must use an access token with
// the repo scope or security_events scope.
//
// GitHub API docs: https://docs.github.com/rest/secret-scanning/secret-scanning#update-a-secret-scanning-alert
//
//meta:operation PATCH /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}
func UpdateAlertInternal(ctx context.Context, client *github.Client, owner string, repo string, number int64, opts *SecretScanningAlertUpdateOptionsInternal) (*github.SecretScanningAlert, *github.Response, error) {
	u := fmt.Sprintf("repos/%v/%v/secret-scanning/alerts/%v", owner, repo, number)

	req, err := client.NewRequest("PATCH", u, opts)
	if err != nil {
		return nil, nil, err
	}

	var alert *github.SecretScanningAlert
	resp, err := client.Do(ctx, req, &alert)
	if err != nil {
		return nil, resp, err
	}

	return alert, resp, nil
}

type AlertResolutionParams struct {
	EnterpriseName           string
	OrganizationIDs          *[]string
	RepositoryIDs            *[]string
	OldPattern               string
	NewPattern               string
	OldPatternSubstringRegex string
	NewPatternSubstringRegex string
	DryRun                   bool
}

func resolveAlreadyTriagedAlerts(ctx context.Context, params AlertResolutionParams, client *github.Client) error {
	// Populate repo->alert maps of the old and new pattern alerts.
	// Specify the state as "resolved" for the old pattern and "open" for the new pattern.
	oldPatternAlertsByRepoKey := make(map[RepoKey][]*github.SecretScanningAlert)
	newPatternAlertsByRepoKey := make(map[RepoKey][]*github.SecretScanningAlert)

	oldPatternOptions := github.SecretScanningAlertListOptions{
		ListCursorOptions: github.ListCursorOptions{PerPage: 100},
		ListOptions:       github.ListOptions{PerPage: 100},
		State:             "resolved",
		SecretType:        params.OldPattern,
	}
	newPatternOptions := github.SecretScanningAlertListOptions{
		ListCursorOptions: github.ListCursorOptions{PerPage: 100},
		ListOptions:       github.ListOptions{PerPage: 100},
		State:             "open",
		SecretType:        params.NewPattern,
	}

	// Get all alerts for the old and new patterns.
	if params.EnterpriseName != "" {
		log.Printf("Getting alerts for enterprise %s\n", params.EnterpriseName)
		err := getEnterpriseSecretScanningAlerts(ctx, client, params.EnterpriseName, params.OldPattern, oldPatternOptions, oldPatternAlertsByRepoKey)
		if err != nil {
			log.Fatalf("Error getting old pattern alerts for enterprise %s: %s\n", params.EnterpriseName, err)
			return err
		}
		err = getEnterpriseSecretScanningAlerts(ctx, client, params.EnterpriseName, params.NewPattern, newPatternOptions, newPatternAlertsByRepoKey)
		if err != nil {
			log.Fatalf("Error getting new pattern alerts for enterprise %s: %s\n", params.EnterpriseName, err)
			return err
		}
	} else if len(*params.OrganizationIDs) > 0 {
		for _, orgID := range *params.OrganizationIDs {
			log.Printf("Getting alerts for organization %s\n", orgID)
			err := getOrganizationSecretScanningAlerts(ctx, client, orgID, params.OldPattern, oldPatternOptions, oldPatternAlertsByRepoKey)
			if err != nil {
				log.Fatalf("Error getting old pattern alerts for organization %s: %s\n", orgID, err)
				return err
			}
			err = getOrganizationSecretScanningAlerts(ctx, client, orgID, params.NewPattern, newPatternOptions, newPatternAlertsByRepoKey)
			if err != nil {
				log.Fatalf("Error getting new pattern alerts for organization %s: %s\n", orgID, err)
				return err
			}
		}
	} else if len(*params.RepositoryIDs) > 0 {
		for _, repoID := range *params.RepositoryIDs {
			splitRepoID := strings.Split(repoID, "/")
			if len(splitRepoID) != 2 {
				log.Fatalf("Error: repositoryID %s is invalid. Must be in the format owner/name\n", repoID)
				return nil
			}
			repoKey := RepoKey{Owner: splitRepoID[0], Name: splitRepoID[1]}

			log.Printf("Getting alerts for repository %s\n", repoID)

			err := getRepositorySecretScanningAlerts(ctx, client, repoKey, params.OldPattern, oldPatternOptions, oldPatternAlertsByRepoKey)
			if err != nil {
				log.Fatalf("Error getting old pattern alerts for repository %s: %s\n", repoID, err)
				return err
			}
			err = getRepositorySecretScanningAlerts(ctx, client, repoKey, params.NewPattern, newPatternOptions, newPatternAlertsByRepoKey)
			if err != nil {
				log.Fatalf("Error getting new pattern alerts for repository %s: %s\n", repoID, err)
				return err
			}
		}
	} else {
		// Should never happen
		log.Fatalf("Error: enterpriseName, organizationIDs, and repositoryIDs cannot all be empty\n")
		return nil
	}

	// Count the number of old and new alerts in each map and print the results.
	oldPatternAlertCount := 0
	for _, alerts := range oldPatternAlertsByRepoKey {
		oldPatternAlertCount += len(alerts)
	}
	log.Printf("Old pattern alert count: %d\n", oldPatternAlertCount)

	newPatternAlertCount := 0
	for _, alerts := range newPatternAlertsByRepoKey {
		newPatternAlertCount += len(alerts)
	}
	log.Printf("New pattern alert count: %d\n", newPatternAlertCount)

	// Get the details/locations of the alerts for the old and new patterns.
	oldAlertDetailsByRepo := make(RepoKeyToAlertDetailsToAlertMap)
	newAlertDetailsByRepo := make(RepoKeyToAlertDetailsToAlertMap)

	err := getSecretScanningAlertLocations(ctx, params.OldPatternSubstringRegex, oldPatternAlertsByRepoKey, client, oldAlertDetailsByRepo)
	if err != nil {
		log.Fatalf("Error getting old pattern alert details: %s\n", err)
		return err
	}

	err = getSecretScanningAlertLocations(ctx, params.NewPatternSubstringRegex, newPatternAlertsByRepoKey, client, newAlertDetailsByRepo)
	if err != nil {
		log.Fatalf("Error getting new pattern alert details: %s\n", err)
		return err
	}

	oldPatternAlertLocationCount := 0
	newPatternAlertLocationCount := 0

	for _, alerts := range oldAlertDetailsByRepo {
		oldPatternAlertLocationCount += len(alerts)
	}

	for _, alerts := range newAlertDetailsByRepo {
		newPatternAlertLocationCount += len(alerts)
	}

	log.Printf("Processing %d old pattern locations\n", oldPatternAlertLocationCount)
	log.Printf("Processing %d new pattern locations\n", newPatternAlertLocationCount)

	// Correlate the old and new pattern alerts by repo, location, and secret.
	// If the same location/secret is found in the same repo both maps, resolve the new alert.
	// If the same location/secret is not found in the same repo in both maps, the alert is new and should not be resolved.
	alertsToResolve := make(map[AlertKeyAndURL]*github.SecretScanningAlert)

	for repo, oldAlertsByDetails := range oldAlertDetailsByRepo {
		// If the old alert repo has new pattern alert locations, process it.
		if newAlertsByDetails, ok := newAlertDetailsByRepo[repo]; ok {
			// Correlate old locations to new locations and add the new alerts to the alertsToResolve map.
			for oldAlertDetails, oldAlert := range oldAlertsByDetails {
				if newAlert, ok := newAlertsByDetails[oldAlertDetails]; ok {
					alertKeyAndUrl := AlertKeyAndURL{AlertKey: makeAlertKey(newAlert), URL: newAlert.GetHTMLURL()}
					alertsToResolve[alertKeyAndUrl] = oldAlert
				}
			}
		}
	}

	log.Printf("Overlapping alert count: %d\n", len(alertsToResolve))

	// Write the alerts to resolve to a CSV file for auditing.
	file, err := os.Create("resolved_alerts.csv")
	if err != nil {
		log.Fatalf("Error creating CSV output file: %s\n", err)
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()

	for newAlert, oldAlert := range alertsToResolve {
		var operationStatus string
		var operationError string
		if params.DryRun {
			operationStatus = "Would have resolved"
		} else {
			operationStatus = "Resolved"
			oldResolution := oldAlert.GetResolution()
			oldResolutionComment := oldAlert.GetResolutionComment()
			opts := SecretScanningAlertUpdateOptionsInternal{
				State:             oldAlert.GetState(),
				Resolution:        &oldResolution,
				ResolutionComment: &oldResolutionComment,
			}
			_, _, err := UpdateAlertInternal(
				ctx,
				client,
				newAlert.AlertKey.Repo.Owner,
				newAlert.AlertKey.Repo.Name,
				newAlert.AlertKey.Number,
				&opts,
			)
			if err != nil {
				operationError = err.Error()
			}
		}

		// Write the action to the CSV file.
		record := []string{
			newAlert.URL,
			oldAlert.GetHTMLURL(),
			operationStatus,
			operationError,
		}
		if err := writer.Write(record); err != nil {
			log.Fatalf("Error writing to CSV output file: %s\n", err)
			return err
		}
	}

	return nil
}

func main() {
	app := &cli.App{
		Name:  "GitHub Secret Scanning Automation",
		Usage: "Automate reopening/resolving secret scanning alerts",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "url",
				Usage:    "The GitHub endpoint URL",
				Value:    "https://github.com/",
				Required: false,
			},
			&cli.BoolFlag{
				Name:  "dry-run",
				Value: false,
				Usage: "Run without making changes",
			},
			&cli.PathFlag{
				Name:     "alerts-to-reopen-csv",
				Usage:    "CSV file path with alerts to reopen (owner, repo, alert number)",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "pat",
				Usage:    "GitHub personal access token",
				Required: true,
				EnvVars:  []string{"GITHUB_TOKEN"},
			},
			&cli.StringFlag{
				Name:     "enterprise-id",
				Usage:    "GitHub Enterprise identifier",
				Required: false,
			},
			&cli.StringSliceFlag{
				Name:     "organization-ids",
				Usage:    "Comma-delimited list of organization names",
				Required: false,
			},
			&cli.StringSliceFlag{
				Name:     "repository-ids",
				Usage:    "Comma-delimited list of repository names in the format 'org/repo'",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "old-pattern",
				Usage:    "Old secret scanning pattern",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "new-pattern",
				Usage:    "New secret scanning pattern",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "old-substring-regex",
				Usage:    "Old secret substring regex used for correlating secret scanning alerts. WARNING: Does not support multi-line alerts.",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "new-substring-regex",
				Usage:    "New secret substring regex used for correlating secret scanning alerts. WARNING: Does not support multi-line alerts.",
				Required: false,
			},
		},
		Action: func(c *cli.Context) error {
			apiUrl := c.String("url")
			dryRun := c.Bool("dry-run")
			pat := c.String("pat")
			alertsCsv := c.Path("alerts-to-reopen-csv")
			enterpriseId := c.String("enterprise-id")
			organizationIDs := c.StringSlice("organization-ids")
			repositoryIDs := c.StringSlice("repository-ids")
			oldSecretPattern := c.String("old-pattern")
			newSecretPattern := c.String("new-pattern")
			oldSubstringRegex := c.String("old-substring-regex")
			newSubstringRegex := c.String("new-substring-regex")

			// Ensure mutual exclusivity of enterprise, organization, and repository flags
			levelCount := 0
			if enterpriseId != "" {
				levelCount++
			}
			if len(organizationIDs) > 0 {
				levelCount++
			}
			if len(repositoryIDs) > 0 {
				levelCount++
			}
			if levelCount > 1 {
				log.Fatalf("Only one of enterprise-id, organization-names, or repository-names can be specified")
				return nil
			}

			if alertsCsv == "" && (oldSecretPattern == "" || newSecretPattern == "") {
				log.Fatalf("Must specify at least alerts-csv or old-secret-pattern and new-secret-pattern.")
				return nil
			}

			log.Printf("API URL: %s\n", apiUrl)
			log.Printf("Dry Run: %v\n", dryRun)
			log.Printf("Alerts CSV Path: %s\n", alertsCsv)
			log.Printf("Enterprise ID: %s\n", enterpriseId)
			log.Printf("Organization Names: %v\n", organizationIDs)
			log.Printf("Repository Names: %v\n", repositoryIDs)
			log.Printf("Old Secret Pattern: %s\n", oldSecretPattern)
			log.Printf("New Secret Pattern: %s\n", newSecretPattern)
			log.Printf("Old Substring Regex: %s\n", oldSubstringRegex)
			log.Printf("New Substring Regex: %s\n", newSubstringRegex)

			// Set up OAuth2 authentication with the token
			ctx := context.Background()
			ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: pat})
			tc := oauth2.NewClient(ctx, ts)

			// Parse the URL and create a new GitHub client
			baseURL, err := url.Parse(apiUrl)
			if err != nil {
				log.Fatalf("Error parsing URL: %s\n", err)
				return err
			}

			client, err := github.NewClient(tc).WithEnterpriseURLs(baseURL.String(), baseURL.String())
			if err != nil {
				log.Fatalf("Error creating GitHub client: %s\n", err)
				return err
			}

			if alertsCsv != "" {
				log.Printf("Beginning secret scanning alert reopening.\n")
				err := reopenClosedAlertsFromCSV(ctx, alertsCsv, dryRun, client)
				if err != nil {
					log.Fatalf("Error reopening alerts: %s\n", err)
					return err
				}
				log.Printf("Finished secret scanning alert reopening.\n")
			} else {
				log.Printf("Alert CSV input path not specified, skipping secret scanning alert reopening.\n")
			}

			if oldSecretPattern == "" || newSecretPattern == "" {
				log.Printf("Old secret pattern and new secret pattern not specified, skipping secret scanning pattern migration.\n")
				return nil
			}

			log.Printf("Beginning secret scanning pattern migration.\n")

			resolutionParams := AlertResolutionParams{
				EnterpriseName:           enterpriseId,
				OrganizationIDs:          &organizationIDs,
				RepositoryIDs:            &repositoryIDs,
				OldPattern:               oldSecretPattern,
				NewPattern:               newSecretPattern,
				OldPatternSubstringRegex: oldSubstringRegex,
				NewPatternSubstringRegex: newSubstringRegex,
				DryRun:                   dryRun,
			}

			err = resolveAlreadyTriagedAlerts(ctx, resolutionParams, client)
			if err == nil {
				log.Printf("Finished secret scanning pattern migration.\n")
			}
			return err
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

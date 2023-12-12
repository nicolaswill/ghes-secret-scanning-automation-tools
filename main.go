package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strconv"
	"sync"

	"github.com/google/go-github/v57/github"
	"github.com/urfave/cli/v2"
	"golang.org/x/oauth2"
)

type alertKey struct {
	owner  string
	repo   string
	number int64
}

type alertLocation struct {
	secret       string
	repoOwner    string
	repoName     string
	locationType string
	commitSHA    string
	startColumn  int
	endColumn    int
	startLine    int
	endLine      int
	path         string
}

// make a struct from a secretscanning alert and location
func makeAlertLocation(alert *github.SecretScanningAlert, location *github.SecretScanningAlertLocation) alertLocation {
	return alertLocation{
		secret:       alert.GetSecret(),
		repoOwner:    alert.GetRepository().GetOwner().GetLogin(),
		repoName:     alert.GetRepository().GetName(),
		locationType: location.GetType(),
		commitSHA:    location.GetDetails().GetCommitSHA(),
		startColumn:  location.GetDetails().GetStartColumn(),
		endColumn:    location.GetDetails().GetEndColumn(),
		startLine:    location.GetDetails().GetStartline(),
		endLine:      location.GetDetails().GetEndLine(),
		path:         location.GetDetails().GetPath(),
	}
}

func makeAlertKey(alert *github.SecretScanningAlert) alertKey {
	return alertKey{
		owner:  alert.GetRepository().GetOwner().GetLogin(),
		repo:   alert.GetRepository().GetName(),
		number: int64(alert.GetNumber()),
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
				log.Fatalf("Error reopening alert: %s\n", err)
				return err
			}
		} else {
			log.Printf("Would have reopened alert %d in %s/%s\n", alertNumber, owner, repo)
		}
	}
	return nil
}

func getSecretScanningAlertLocations(ctx context.Context, client *github.Client, alertsByRepoName map[string][]*github.SecretScanningAlert, alertsByLocation map[alertLocation]*github.SecretScanningAlert) error {
	var wg sync.WaitGroup
	var mutex sync.RWMutex
	semaphore := make(chan struct{}, 32) // up to 32 concurrent goroutines

	for _, alerts := range alertsByRepoName {
		for _, alert := range alerts {
			wg.Add(1)
			semaphore <- struct{}{}
			go func(alert *github.SecretScanningAlert) {
				defer wg.Done()
				defer func() { <-semaphore }()
				locationOpts := github.ListOptions{PerPage: 100, Page: 1}
				for {
					locations, resp, err := client.SecretScanning.ListLocationsForAlert(
						ctx,
						alert.GetRepository().GetOwner().GetLogin(),
						alert.GetRepository().GetName(),
						int64(alert.GetNumber()),
						&locationOpts,
					)
					if err != nil {
						log.Fatalf("Error getting alert locations: %s\n", err)
						return
					}
					if len(locations) == 0 {
						log.Printf("No locations found for alert %d\n", alert.GetNumber())
					}

					for _, location := range locations {
						locationKey := makeAlertLocation(alert, location)
						mutex.Lock()
						alertsByLocation[locationKey] = alert
						mutex.Unlock()
					}

					if resp.NextPage == 0 {
						break
					}
					locationOpts.Page = resp.NextPage
				}
			}(alert)
		}
	}

	wg.Wait()
	return nil
}

func getEnterpriseSecretScanningAlerts(ctx context.Context, enterpriseName string, pattern string, client *github.Client, opts github.SecretScanningAlertListOptions, alertsByRepoName map[string][]*github.SecretScanningAlert) error {
	for {
		alerts, resp, err := client.SecretScanning.ListAlertsForEnterprise(ctx, enterpriseName, &opts)
		if err != nil {
			return err
		}
		for _, alert := range alerts {
			alertsByRepoName[alert.GetRepository().GetFullName()] =
				append(alertsByRepoName[alert.GetRepository().GetFullName()], alert)
		}
		if resp.After == "" {
			break
		}
		opts.ListCursorOptions.After = resp.After
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

func resolveAlreadyTriagedAlerts(ctx context.Context, enterpriseName string, oldPattern string, newPattern string, err error, client *github.Client, dryRun bool) error {
	// Populate repo->alert maps of the old and new pattern alerts.
	// Specify the state as "resolved" for the old pattern and "open" for the new pattern.
	oldPatternAlertsByRepoName := make(map[string][]*github.SecretScanningAlert)
	newPatternAlertsByRepoName := make(map[string][]*github.SecretScanningAlert)

	oldPatternOptions := github.SecretScanningAlertListOptions{
		ListCursorOptions: github.ListCursorOptions{PerPage: 100},
		State:             "resolved",
		SecretType:        oldPattern,
	}
	newPatternOptions := github.SecretScanningAlertListOptions{
		ListCursorOptions: github.ListCursorOptions{PerPage: 100},
		State:             "open",
		SecretType:        newPattern,
	}

	// Get all alerts for the old and new patterns.
	log.Printf("Getting old pattern alerts\n")
	err = getEnterpriseSecretScanningAlerts(ctx, enterpriseName, oldPattern, client, oldPatternOptions, oldPatternAlertsByRepoName)
	if err != nil {
		log.Fatalf("Error getting old pattern alerts: %s\n", err)
		return err
	}

	log.Printf("Getting new pattern alerts\n")
	err = getEnterpriseSecretScanningAlerts(ctx, enterpriseName, newPattern, client, newPatternOptions, newPatternAlertsByRepoName)
	if err != nil {
		log.Fatalf("Error getting new pattern alerts: %s\n", err)
		return err
	}

	// Count the number of old and new alerts in each map and print the results.
	oldPatternAlertCount := 0
	for _, alerts := range oldPatternAlertsByRepoName {
		oldPatternAlertCount += len(alerts)
	}
	log.Printf("Old pattern alert count: %d\n", oldPatternAlertCount)

	newPatternAlertCount := 0
	for _, alerts := range newPatternAlertsByRepoName {
		newPatternAlertCount += len(alerts)
	}
	log.Printf("New pattern alert count: %d\n", newPatternAlertCount)

	// Get the locations of the alerts for the old and new patterns.
	oldPatternAlertLocations := make(map[alertLocation]*github.SecretScanningAlert)
	newPatternAlertLocations := make(map[alertLocation]*github.SecretScanningAlert)

	errCh := make(chan error, 2)
	go func() {
		log.Printf("Getting old pattern alert locations\n")
		err := getSecretScanningAlertLocations(ctx, client, oldPatternAlertsByRepoName, oldPatternAlertLocations)
		errCh <- err
	}()
	go func() {
		log.Printf("Getting new pattern alert locations\n")
		err := getSecretScanningAlertLocations(ctx, client, newPatternAlertsByRepoName, newPatternAlertLocations)
		errCh <- err
	}()
	for i := 0; i < 2; i++ {
		err := <-errCh
		if err != nil {
			log.Fatalf("Error getting pattern alert locations: %s\n", err)
			return err
		}

	}
	close(errCh)

	// Correlate the old and new pattern alerts by location.
	// If the same location is found in both maps, resolve the new alert.
	// If the same location is not found in both maps, the alert is new and should not be resolved.
	log.Printf("Processing %d old pattern locations\n", len(oldPatternAlertLocations))
	log.Printf("Processing %d new pattern locations\n", len(newPatternAlertLocations))

	// A map of new alerts to old alerts - the old alerts must be cross-referenced in order for
	// their resolution and resolution comment to be transferred to the new resolved alerts.
	alertsToResolve := make(map[alertKey]*github.SecretScanningAlert)

	for oldLocation, oldAlert := range oldPatternAlertLocations {
		if newAlert, ok := newPatternAlertLocations[oldLocation]; ok {
			alertsToResolve[makeAlertKey(newAlert)] = oldAlert
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

	for newAlertKey, oldAlert := range alertsToResolve {
		var operationStatus string
		var operationError string

		if dryRun {
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
				newAlertKey.owner,
				newAlertKey.repo,
				newAlertKey.number,
				&opts,
			)
			if err != nil {
				operationError = err.Error()
			}
		}

		// Write the action to the CSV file.
		record := []string{
			newAlertKey.owner,
			newAlertKey.repo,
			strconv.FormatInt(newAlertKey.number, 10),
			oldAlert.GetRepository().GetOwner().GetLogin(),
			oldAlert.GetRepository().GetName(),
			strconv.Itoa(oldAlert.GetNumber()),
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
		Name:  "GitHub Orgs",
		Usage: "List organizations from GitHub",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "url",
				Usage:    "GitHub instance API URL",
				Required: true,
			},
			&cli.BoolFlag{
				Name:  "dry-run",
				Value: false,
				Usage: "Enable dry run mode",
			},
			&cli.PathFlag{
				Name:     "reopen-alerts-csv-path",
				Usage:    "Path to a CSV file containing a list of alerts to reopen in owner,repo,alert-number format",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "pat",
				Usage:    "GitHub personal access token",
				Required: false,
				EnvVars:  []string{"GITHUB_TOKEN"},
			},
			&cli.StringFlag{
				Name:     "enterprise-name",
				Usage:    "GitHub Enterprise name",
				Value:    "github",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "old-pattern",
				Usage:    "Old secret scanning pattern name",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "new-pattern",
				Usage:    "New secret-scanning pattern name",
				Required: false,
			},
		},
		Action: func(c *cli.Context) error {
			instanceURL := c.String("url")
			enterpriseName := c.String("enterprise-name")
			dryRun := c.Bool("dry-run")
			pat := c.String("pat")
			reopenAlertsPath := c.Path("reopen-alerts-csv-path")
			oldPattern := c.String("old-pattern")
			newPattern := c.String("new-pattern")

			log.Printf("Instance URL: %s\n", instanceURL)
			log.Printf("Enterprise name: %s\n", enterpriseName)
			log.Printf("Dry Run: %v\n", dryRun)
			log.Printf("Reopen Alerts Path: %s\n", reopenAlertsPath)
			log.Printf("Old Pattern: %s\n", oldPattern)
			log.Printf("New Pattern: %s\n", newPattern)

			if dryRun {
				log.Println("Dry run enabled, not performing write operations.")
			}

			if reopenAlertsPath == "" && (oldPattern == "" || newPattern == "") {
				log.Fatalf("Must specify at least reopen-alerts or old-pattern and new-pattern.")
				return nil
			}

			// Set up OAuth2 authentication with the token
			ctx := context.Background()
			ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: pat})
			tc := oauth2.NewClient(ctx, ts)

			// Parse the URL and create a new GitHub client
			baseURL, err := url.Parse(instanceURL)
			if err != nil {
				log.Fatalf("Error parsing URL: %s\n", err)
				return err
			}

			client, err := github.NewClient(tc).WithEnterpriseURLs(baseURL.String(), baseURL.String())
			if err != nil {
				log.Fatalf("Error creating GitHub client: %s\n", err)
				return err
			}

			if reopenAlertsPath != "" {
				log.Printf("Beginning secret scanning alert reopening.\n")
				err := reopenClosedAlertsFromCSV(ctx, reopenAlertsPath, dryRun, client)
				if err != nil {
					log.Fatalf("Error reopening alerts: %s\n", err)
					return err
				}
				log.Printf("Finished secret scanning alert reopening.\n")
			} else {
				log.Printf("Alert CSV input path not specified, skipping secret scanning alert reopening.\n")
			}

			if oldPattern == "" || newPattern == "" {
				log.Printf("Old pattern and new pattern not specified, skipping secret scanning pattern migration.\n")
				return nil
			}

			log.Printf("Beginning secret scanning pattern migration.\n")
			err = resolveAlreadyTriagedAlerts(ctx, enterpriseName, oldPattern, newPattern, err, client, dryRun)
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

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

// Secret scanning alert content, type, location, and path.
type AlertDetails struct {
	Secret       string // might be parsed or empty if substringRegex or fuzzyMatching is used
	LocationType string
	CommitSHA    string
	StartColumn  int
	EndColumn    int
	StartLine    int
	EndLine      int
	Path         string
}

type AlertState struct {
	Key               AlertKey
	URL               string
	Resolution        string
	ResolutionComment string
	Secret            string // actual secret content
}

// Map of repo name to alert details to alert state
type RepoKeyToAlertDetailsToAlertState map[RepoKey]map[AlertDetails]AlertState

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

func adjustAlertDetailsWithSubstringRegex(substringRegex *regexp.Regexp, details *AlertDetails, state *AlertState) {
	if substringRegex != nil {
		// get the string index of the first group of the regex
		substringIndex := substringRegex.FindStringSubmatchIndex(details.Secret)
		if len(substringIndex) >= 4 && substringIndex[3]-substringIndex[2] > 0 {
			if details.StartLine == details.EndLine {
				details.EndColumn = substringIndex[3] + details.StartColumn
				details.StartColumn += substringIndex[2]
			} else {
				log.Printf("Warning: startline and endline are different for alert %s. Ignoring column start/end.\n", state.URL)
				details.EndColumn = 0
				details.StartColumn = 0
			}
			details.Secret = details.Secret[substringIndex[2]:substringIndex[3]]
		}
	}
}

// Make a struct containing the secret scanning alert content, type, location, and path.
// While doing so, run the substring regex and adjust the startline/endline based on the location of the substring within the original Secret.
func makeAlertDetails(alert *github.SecretScanningAlert, location *github.SecretScanningAlertLocation, substringRegex *regexp.Regexp, fuzzyMatching bool) AlertDetails {
	var result AlertDetails

	if fuzzyMatching {
		result = AlertDetails{
			Secret:       "",
			LocationType: location.GetType(),
			CommitSHA:    location.GetDetails().GetCommitSHA(),
			StartColumn:  location.GetDetails().GetStartColumn(),
			EndColumn:    location.GetDetails().GetEndColumn(),
			StartLine:    location.GetDetails().GetStartline(),
			EndLine:      location.GetDetails().GetEndLine(),
			Path:         location.GetDetails().GetPath(),
		}
	} else {
		result = AlertDetails{
			Secret:       alert.GetSecret(),
			LocationType: location.GetType(),
			CommitSHA:    location.GetDetails().GetCommitSHA(),
			StartColumn:  location.GetDetails().GetStartColumn(),
			EndColumn:    location.GetDetails().GetEndColumn(),
			StartLine:    location.GetDetails().GetStartline(),
			EndLine:      location.GetDetails().GetEndLine(),
			Path:         location.GetDetails().GetPath(),
		}
	}

	if substringRegex != nil && !fuzzyMatching {
		alertState := makeAlertState(alert)
		adjustAlertDetailsWithSubstringRegex(substringRegex, &result, &alertState)
	}

	return result
}

func makeAlertState(alert *github.SecretScanningAlert) AlertState {
	return AlertState{Key: makeAlertKey(alert), URL: alert.GetHTMLURL(), Resolution: alert.GetResolution(), ResolutionComment: alert.GetResolutionComment(), Secret: alert.GetSecret()}
}

func getSecretScanningAlertLocations(ctx context.Context, client *github.Client, alertsByRepoName map[RepoKey][]*github.SecretScanningAlert, secretSubstringRegex string, fuzzyMatching bool) (RepoKeyToAlertDetailsToAlertState, error) {
	output := make(RepoKeyToAlertDetailsToAlertState)

	var wg sync.WaitGroup
	var mutex sync.RWMutex
	semaphore := make(chan struct{}, 64) // up to 64 concurrent goroutines

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
						return
					}
					if len(locations) == 0 {
						log.Printf("No locations found for alert %d\n", alert.GetNumber())
					}
					for _, location := range locations {
						alertDetails := makeAlertDetails(alert, location, substringRegex, fuzzyMatching)
						alertState := makeAlertState(alert)
						mutex.Lock()
						if _, ok := output[repo]; !ok {
							output[repo] = make(map[AlertDetails]AlertState)
						}
						output[repo][alertDetails] = alertState
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
	return output, nil
}

func getEnterpriseSecretScanningAlerts(ctx context.Context, client *github.Client, enterpriseName string, pattern string, opts github.SecretScanningAlertListOptions, output map[RepoKey][]*github.SecretScanningAlert) error {
	for {
		alerts, resp, err := client.SecretScanning.ListAlertsForEnterprise(ctx, enterpriseName, &opts)
		if err != nil {
			return err
		}
		for _, alert := range alerts {
			repoKey := RepoKey{Owner: alert.GetRepository().GetOwner().GetLogin(), Name: alert.GetRepository().GetName()}
			output[repoKey] = append(output[repoKey], alert)
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
	OldAlerts RepoKeyToAlertDetailsToAlertState
	NewAlerts RepoKeyToAlertDetailsToAlertState
	DryRun    bool
}

type AlertRetrievalParams struct {
	EnterpriseName  string
	OrganizationIDs *[]string
	RepositoryIDs   *[]string
	PatternID       string
	AlertState      string
	SubstringRegex  string
	FuzzyMatching   bool
}

func retrieveAlertsAndLocations(ctx context.Context, params AlertRetrievalParams, client *github.Client) (RepoKeyToAlertDetailsToAlertState, error) {
	alertsByRepoKey := make(map[RepoKey][]*github.SecretScanningAlert)

	alertListOptions := github.SecretScanningAlertListOptions{
		ListCursorOptions: github.ListCursorOptions{PerPage: 100},
		ListOptions:       github.ListOptions{PerPage: 100},
		State:             params.AlertState,
		SecretType:        params.PatternID,
	}

	// Get all alerts for the old and new patterns.
	if params.EnterpriseName != "" {
		log.Printf("Getting %s alerts for enterprise %s\n", params.PatternID, params.EnterpriseName)
		err := getEnterpriseSecretScanningAlerts(ctx, client, params.EnterpriseName, params.PatternID, alertListOptions, alertsByRepoKey)
		if err != nil {
			return nil, fmt.Errorf("error getting alerts for enterprise %s: %s", params.EnterpriseName, err)
		}
	} else if len(*params.OrganizationIDs) > 0 {
		for _, orgID := range *params.OrganizationIDs {
			log.Printf("Getting %s alerts for organization %s\n", params.PatternID, orgID)
			err := getOrganizationSecretScanningAlerts(ctx, client, orgID, params.PatternID, alertListOptions, alertsByRepoKey)
			if err != nil {
				return nil, fmt.Errorf("error getting alerts for organization %s: %s", orgID, err)
			}
		}
	} else if len(*params.RepositoryIDs) > 0 {
		for _, repoID := range *params.RepositoryIDs {
			splitRepoID := strings.Split(repoID, "/")
			if len(splitRepoID) != 2 {
				return nil, fmt.Errorf("repositoryID %s is invalid. Must be in the format owner/name", repoID)
			}
			repoKey := RepoKey{Owner: splitRepoID[0], Name: splitRepoID[1]}
			log.Printf("Getting %s alerts for repository %s\n", params.PatternID, repoID)
			err := getRepositorySecretScanningAlerts(ctx, client, repoKey, params.PatternID, alertListOptions, alertsByRepoKey)
			if err != nil {
				return nil, fmt.Errorf("error getting alerts for repository %s: %s", repoID, err)
			}
		}
	} else {
		return nil, fmt.Errorf("enterpriseName, organizationIDs, and repositoryIDs cannot all be empty")
	}

	// Loop through all repos in the output and remove any that are disabled
	for repoKey := range alertsByRepoKey {
		_, resp, err := client.Repositories.Get(ctx, repoKey.Owner, repoKey.Name)
		if err != nil && resp.StatusCode == 403 && strings.Contains(err.Error(), "Repository access blocked") {
			log.Printf("Warning: repository %s/%s is disabled\n", repoKey.Owner, repoKey.Name)
			delete(alertsByRepoKey, repoKey)
		}
	}

	// Count the number of old and new alerts in each map and print the results.
	alertCount := 0
	for _, alerts := range alertsByRepoKey {
		alertCount += len(alerts)
	}
	log.Printf("Retrieved %d alerts for pattern %s\n", alertCount, params.PatternID)

	// Retrieve the details/locations of the alerts
	alertDetailsByRepo, err := getSecretScanningAlertLocations(ctx, client, alertsByRepoKey, params.SubstringRegex, params.FuzzyMatching)
	if err != nil {
		return nil, fmt.Errorf("error getting alert details: %s", err)
	}
	return alertDetailsByRepo, nil
}

func resolveAlreadyTriagedAlerts(ctx context.Context, params AlertResolutionParams, client *github.Client) error {
	oldPatternAlertLocationCount := 0
	newPatternAlertLocationCount := 0

	for _, alerts := range params.OldAlerts {
		oldPatternAlertLocationCount += len(alerts)
	}

	for _, alerts := range params.NewAlerts {
		newPatternAlertLocationCount += len(alerts)
	}

	log.Printf("Processing %d old pattern locations\n", oldPatternAlertLocationCount)
	log.Printf("Processing %d new pattern locations\n", newPatternAlertLocationCount)

	// Correlate the old and new pattern alerts by repo and details:
	// If the same repo and details are found in both maps, resolve the new alert.
	// If the same repo and details are NOT found in both maps, the alert is new and should not be resolved.
	type AlertResolutionInfo struct {
		NewAlert AlertState
		OldAlert AlertState
	}
	alertsToResolve := make(map[AlertKey]AlertResolutionInfo)
	for repo, oldAlertStateByDetails := range params.OldAlerts {
		// If the old alert repo has new pattern alert details, process it.
		if newAlertStateByDetails, ok := params.NewAlerts[repo]; ok {
			// Correlate old details to new details and add the new alerts to the alertsToResolve map.
			for oldAlertDetails, oldAlertState := range oldAlertStateByDetails {
				if newAlertState, ok := newAlertStateByDetails[oldAlertDetails]; ok {
					info := AlertResolutionInfo{NewAlert: newAlertState, OldAlert: oldAlertState}
					alertsToResolve[oldAlertState.Key] = info
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

	var wg sync.WaitGroup
	var mu sync.Mutex

	semaphore := make(chan struct{}, 64)

	for _, info := range alertsToResolve {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(info AlertResolutionInfo) {
			defer wg.Done()
			defer func() { <-semaphore }()

			var operationStatus string
			var operationError string
			if params.DryRun {
				operationStatus = "Would have resolved"
			} else {
				operationStatus = "Resolved"
				opts := SecretScanningAlertUpdateOptionsInternal{
					State:             "resolved",
					Resolution:        &info.OldAlert.Resolution,
					ResolutionComment: &info.OldAlert.ResolutionComment,
				}
				_, _, err := UpdateAlertInternal(
					ctx,
					client,
					info.NewAlert.Key.Repo.Owner,
					info.NewAlert.Key.Repo.Name,
					info.NewAlert.Key.Number,
					&opts,
				)
				if err != nil {
					operationError = err.Error()
				}
			}

			record := []string{
				info.NewAlert.Secret,
				info.NewAlert.URL,
				info.OldAlert.Secret,
				info.OldAlert.URL,
				operationStatus,
				operationError,
			}
			mu.Lock()
			if err := writer.Write(record); err != nil {
				log.Fatalf("Error writing to CSV output file: %s\n", err)
			}
			mu.Unlock()
		}(info)
	}

	wg.Wait()

	return nil
}

func writeAlertsToCSV(alertsByRepoKey RepoKeyToAlertDetailsToAlertState, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating CSV output file: %s", err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()

	for repoKey, alerts := range alertsByRepoKey {
		for details, state := range alerts {
			record := []string{
				repoKey.Owner,                           // 1
				repoKey.Name,                            // 2
				details.Secret,                          // 3
				details.CommitSHA,                       // 4
				details.Path,                            // 5
				strconv.Itoa(details.StartLine),         // 6
				strconv.Itoa(details.EndLine),           // 7
				strconv.Itoa(details.StartColumn),       // 8
				strconv.Itoa(details.EndColumn),         // 9
				details.LocationType,                    // 10
				strconv.FormatInt(state.Key.Number, 10), // 11
				state.URL,                               // 12
				state.Resolution,                        // 13
				state.ResolutionComment,                 // 14
			}
			if err := writer.Write(record); err != nil {
				return fmt.Errorf("could not write to CSV output file: %s", err)
			}
		}
	}

	return nil
}

func readAlertsFromCSV(filename string, fuzzyMatching bool, substringRegexStr string) (RepoKeyToAlertDetailsToAlertState, error) {
	alertsByRepoKey := make(RepoKeyToAlertDetailsToAlertState)

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open CSV input file: %s", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = 14
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("error reading CSV input file: %s", err)
	}

	// compile the regex
	var substringRegex *regexp.Regexp
	if !fuzzyMatching {
		substringRegex, err = regexp.Compile(substringRegexStr)
		if err != nil {
			return nil, fmt.Errorf("error compiling substring regex: %s", err)
		}
	}

	for _, record := range records {
		atoi := func(s string) int {
			i, err := strconv.Atoi(s)
			if err != nil {
				panic(err)
			}
			return i
		}
		repoKey := RepoKey{
			Owner: record[0],
			Name:  record[1],
		}
		details := AlertDetails{
			Secret:       record[2],
			CommitSHA:    record[3],
			Path:         record[4],
			StartLine:    atoi(record[5]),
			EndLine:      atoi(record[6]),
			StartColumn:  atoi(record[7]),
			EndColumn:    atoi(record[8]),
			LocationType: record[9],
		}
		state := AlertState{
			Key: AlertKey{
				Number: int64(atoi(record[10])),
				Repo: RepoKey{
					Owner: repoKey.Owner,
					Name:  repoKey.Name,
				},
			},
			URL:               record[11],
			Resolution:        record[12],
			ResolutionComment: record[13],
			Secret:            details.Secret,
		}

		if fuzzyMatching {
			details.Secret = ""
		} else if substringRegex != nil {
			adjustAlertDetailsWithSubstringRegex(substringRegex, &details, &state)
		}

		if _, ok := alertsByRepoKey[repoKey]; !ok {
			alertsByRepoKey[repoKey] = make(map[AlertDetails]AlertState)
		}
		alertsByRepoKey[repoKey][details] = state
	}

	// log number of alerts read
	alertCount := 0
	for _, alerts := range alertsByRepoKey {
		alertCount += len(alerts)
	}
	log.Printf("Read %d alerts/locations from %s\n", alertCount, filename)

	return alertsByRepoKey, nil
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
			&cli.BoolFlag{
				Name:  "fuzzy",
				Value: false,
				Usage: "Enable fuzzy matching for alert correlation",
			},
			&cli.BoolFlag{
				Name:  "output-old-alerts",
				Value: false,
				Usage: "Output old alerts to a CSV file for further processing",
			},
			&cli.PathFlag{
				Name:     "old-alerts-csv",
				Usage:    "CSV file path of old alerts to use as an input, or if output-old-alerts is specified, as an output path",
				Required: false,
			},
			&cli.PathFlag{
				Name:     "alerts-to-reopen-csv",
				Usage:    "CSV file path with alerts to reopen (owner, repo, alert number)",
				Required: false,
			},
		},
		Action: func(c *cli.Context) error {
			apiUrl := c.String("url")
			dryRun := c.Bool("dry-run")
			pat := c.String("pat")
			enterpriseId := c.String("enterprise-id")
			organizationIDs := c.StringSlice("organization-ids")
			repositoryIDs := c.StringSlice("repository-ids")
			oldSecretPattern := c.String("old-pattern")
			newSecretPattern := c.String("new-pattern")
			oldSubstringRegex := c.String("old-substring-regex")
			newSubstringRegex := c.String("new-substring-regex")
			fuzzyMatching := c.Bool("fuzzy")
			outputOldAlerts := c.Bool("output-old-alerts")
			oldAlertsCsv := c.Path("old-alerts-csv")
			alertsCsv := c.Path("alerts-to-reopen-csv")

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

			// Do not allow old and new secret patterns to be the same
			if oldSecretPattern == newSecretPattern {
				log.Fatalf("Old and new secret patterns cannot be the same.")
				return nil
			}

			log.Printf("API URL: %s\n", apiUrl)
			log.Printf("Dry Run: %v\n", dryRun)
			log.Printf("Enterprise ID: %s\n", enterpriseId)
			log.Printf("Organization Names: %v\n", organizationIDs)
			log.Printf("Repository Names: %v\n", repositoryIDs)
			log.Printf("Old Secret Pattern: %s\n", oldSecretPattern)
			log.Printf("New Secret Pattern: %s\n", newSecretPattern)
			log.Printf("Old Substring Regex: %s\n", oldSubstringRegex)
			log.Printf("New Substring Regex: %s\n", newSubstringRegex)
			log.Printf("Fuzzy Matching: %v\n", fuzzyMatching)
			log.Printf("Output Old Alerts: %v\n", outputOldAlerts)
			log.Printf("Old Alerts CSV Path: %s\n", oldAlertsCsv)
			log.Printf("Alerts to Reopen CSV Path: %s\n", alertsCsv)

			// Setup the client
			ctx := context.Background()
			ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: pat})
			tc := oauth2.NewClient(ctx, ts)

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

			// Process the alerts-to-reopen CSV
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

			// Process secret scanning patterns
			// Three modes of operation:
			// 1. Output old alerts to CSV and return
			// 2. Populate old alerts from CSV and migrate to new pattern
			// 3. Retrieve old alerts from GitHub and migrate to new pattern
			if oldSecretPattern == "" {
				log.Printf("Old secret pattern not specified, skipping secret scanning pattern migration.\n")
				return nil
			}

			oldAlertRetrievalParams := AlertRetrievalParams{
				EnterpriseName:  enterpriseId,
				OrganizationIDs: &organizationIDs,
				RepositoryIDs:   &repositoryIDs,
				PatternID:       oldSecretPattern,
				SubstringRegex:  oldSubstringRegex,
				FuzzyMatching:   fuzzyMatching,
				AlertState:      "resolved",
			}

			if err != nil {
				log.Fatalf("Error retrieving old alerts: %s\n", err)
				return err
			}

			// Mode 1: Output old alerts to CSV
			if outputOldAlerts {
				oldAlerts, err := retrieveAlertsAndLocations(ctx, oldAlertRetrievalParams, client)
				if err != nil {
					return err
				}
				if oldAlertsCsv == "" {
					return fmt.Errorf("output old alerts specified, but old-alerts-csv not specified")
				}
				log.Printf("Outputting old alerts to CSV.\n")
				return writeAlertsToCSV(oldAlerts, oldAlertsCsv)
			}

			// Mode 2: Populate old alerts from CSV
			if newSecretPattern == "" {
				return fmt.Errorf("new secret pattern not specified, skipping secret scanning pattern migration")
			}

			log.Printf("Beginning secret scanning pattern migration.\n")

			var wg sync.WaitGroup
			errorsChan := make(chan error, 2)
			var oldAlerts RepoKeyToAlertDetailsToAlertState
			var newAlerts RepoKeyToAlertDetailsToAlertState

			wg.Add(1)
			go func() {
				defer wg.Done()
				var err error
				if oldAlertsCsv != "" {
					log.Printf("Populating old alerts from CSV.\n")
					oldAlerts, err = readAlertsFromCSV(oldAlertsCsv, fuzzyMatching, oldSubstringRegex)
				} else {
					oldAlerts, err = retrieveAlertsAndLocations(ctx, oldAlertRetrievalParams, client)
				}
				if err != nil {
					errorsChan <- err
					return
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				newAlertRetrievalParams := AlertRetrievalParams{
					EnterpriseName:  enterpriseId,
					OrganizationIDs: &organizationIDs,
					RepositoryIDs:   &repositoryIDs,
					PatternID:       newSecretPattern,
					SubstringRegex:  newSubstringRegex,
					FuzzyMatching:   fuzzyMatching,
					AlertState:      "open",
				}
				var err error
				newAlerts, err = retrieveAlertsAndLocations(ctx, newAlertRetrievalParams, client)
				if err != nil {
					errorsChan <- err
					return
				}
			}()

			wg.Wait()
			close(errorsChan)

			for err := range errorsChan {
				if err != nil {
					return err
				}
			}

			resolutionParams := AlertResolutionParams{
				OldAlerts: oldAlerts,
				NewAlerts: newAlerts,
				DryRun:    dryRun,
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

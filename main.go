// Threatutil
//
// This program performs some useful operations on JIRA to help with
// threat modeling.  JIRA is a reasonably good fit for this
// information, but doesn't necessarily generate useful output for a
// report.
package main

import (
	"fmt"
	"log"
	"os/user"

	"github.com/andygrunwald/go-jira"
	"github.com/bgentry/go-netrc/netrc"
)

func main() {
	err := queryJira("davidb.atlassian.net", "project = THREAT")
	if err != nil {
		log.Fatal(err)
	}
}

// Query for the issues from JIRA.
func queryJira(host string, query string) error {
	login, err := findPass(host)
	if err != nil {
		return err
	}

	client, err := jira.NewClient(nil, "https://"+host+"/")
	if err != nil {
		return err
	}
	client.Authentication.SetBasicAuth(login.User, login.Password)

	var opt jira.SearchOptions

	result := make([]jira.Issue, 0)
	start := 0

	for {
		// opt.Fields = []string{"summary", "description"}
		opt.StartAt = start
		opt.MaxResults = 50
		issues, resp, err := client.Issue.Search(query, &opt)
		if err != nil {
			return err
		}

		result = append(result, issues...)
		log.Printf("resp: %+v", resp)

		if start+len(issues) == resp.Total {
			break
		}
		start += len(issues)
	}

	for _, issue := range result {
		log.Printf("issue: %+v", issue.ID)
		for k, v := range issue.Fields.Unknowns {
			log.Printf("  %s: %+v", k, v)
		}
	}

	return nil
}

type Login struct {
	User, Password string
}

// Determine the given user's jira password for the given host.
func findPass(host string) (*Login, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	path := usr.HomeDir + "/.netrc"
	n, err := netrc.ParseFile(path)
	if err != nil {
		return nil, err
	}

	m := n.FindMachine(host)
	if m == nil {
		return nil, fmt.Errorf("Unable to find host in ~/.netrc: %q", host)
	}

	return &Login{
		User:     m.Login,
		Password: m.Password,
	}, nil
}

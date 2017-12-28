// Threatutil
//
// This program performs some useful operations on JIRA to help with
// threat modeling.  JIRA is a reasonably good fit for this
// information, but doesn't necessarily generate useful output for a
// report.
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os/user"

	"github.com/andygrunwald/go-jira"
	"github.com/bgentry/go-netrc/netrc"
	"github.com/kr/text"
	"gopkg.in/yaml.v2"
)

func main() {
	if false {
		output()
	} else {
		input()
	}
}

func input() {
	// Try reading the yaml of the threats.
	var threats map[string]*Threat

	buf, err := ioutil.ReadFile("sensor.yaml")
	if err != nil {
		log.Fatal(err)
	}

	err = yaml.Unmarshal(buf, &threats)
	if err != nil {
		log.Fatal(err)
	}

	for id, threat := range threats {
		fmt.Printf("%s: %#v\n", id, threat)
	}
}

func output() {
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

	// Reverse the results, which seem to be in reverse order of
	// creation.
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	// enc := toml.NewEncoder(os.Stdout)
	threats := make(map[string]*Threat)

	for _, issue := range result {
		threat := Threat{
			Summary: issue.Fields.Summary,
			Desc:    issue.Fields.Description,
			Resp:    unknownGet(issue.Fields.Unknowns, "customfield_10203"),
			Sec:     unknownGet(issue.Fields.Unknowns, "customfield_10202"),
			Imp:     unknownGet(issue.Fields.Unknowns, "customfield_10201"),
		}
		threats[issue.Key] = &threat

		fmt.Printf("%s:\n  summary: %s\n", issue.Key, threat.Summary)
		show("desc", threat.Desc)
		show("resp", threat.Resp)
		show("sec", threat.Sec)
		show("imp", threat.Imp)
	}

	return nil
}

func show(key, line string) {
	wrapped := text.Wrap(line, 65)
	indented := text.Indent(wrapped, "    ")
	fmt.Printf("  %s: >-\n%s\n", key, indented)
}

func unknownGet(fields map[string]interface{}, key string) string {
	item, ok := fields[key]
	if !ok {
		return ""
	}

	switch it := item.(type) {
	case string:
		return it
	case nil:
		return ""
	default:
		panic("Unknown type")
	}
}

type Threat struct {
	Summary string
	Desc    string
	Resp    string
	Sec     string
	Imp     string
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

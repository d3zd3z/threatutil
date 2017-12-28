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

	"gopkg.in/yaml.v2"
)

func main() {
	input()
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

type Threat struct {
	Summary string
	Desc    string
	Resp    string
	Sec     string
	Imp     string
}

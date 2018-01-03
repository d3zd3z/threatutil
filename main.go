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
	"regexp"
	"sort"
	"strconv"

	"github.com/kr/text"
	"gopkg.in/yaml.v2"
)

func main() {
	input()
}

func input() {
	// Try reading the yaml of the threats.
	var threats map[string]*Threat

	buf, err := ioutil.ReadFile("threats.yaml")
	if err != nil {
		log.Fatal(err)
	}

	err = yaml.Unmarshal(buf, &threats)
	if err != nil {
		log.Fatal(err)
	}

	GenMD(threats)
}

type Threat struct {
	Summary string
	Applies []string
	Desc    string
	Resp    string
	Sec     string
	Imp     string
}

type KeyedThreat struct {
	Key string
	*Threat
}

// GenMD outputs the threats in a markdown format for inclusion in a
// document.
func GenMD(threats map[string]*Threat) {
	keyed := descrambleThreats(threats)

	for _, th := range keyed {
		if !th.DoesApply("sensor") {
			continue
		}
		fmt.Printf("## %s: %s\n\n", th.Key, th.Summary)

		fmt.Printf("%s\n\n", text.Wrap(th.Desc, 65))
		showField("Threat Response", th.Resp)
		showField("Security Requirement", th.Sec)
		showField("Impact", th.Imp)
	}
}

// showField shows a single field.
func showField(name, data string) {
	if data == "" {
		return
	}

	fmt.Printf("### %s\n\n", name)
	fmt.Printf("%s\n\n", text.Wrap(data, 65))
}

// Unpack all of the threats, sorting them nicely, returns all of the
// keys and all of the threats
func descrambleThreats(threats map[string]*Threat) []KeyedThreat {
	var result []KeyedThreat

	for k, v := range threats {
		result = append(result, KeyedThreat{
			Key:    k,
			Threat: v,
		})
	}

	sort.Sort(KeyedByKey(result))

	return result
}

// KeyedByKey sorts a KeyedThreat slice by the key id, ordered
// numerically.
type KeyedByKey []KeyedThreat

func (p KeyedByKey) Len() int           { return len(p) }
func (p KeyedByKey) Less(i, j int) bool { return keyNum(p[i].Key) < keyNum(p[j].Key) }
func (p KeyedByKey) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

var keyRe = regexp.MustCompile(`^THREAT-(\d+)$`)

// DoesApply determines if this threat applies to a given target.
// This returns true iff Applies contains the given target.
func (t *Threat) DoesApply(target string) bool {
	for _, ap := range t.Applies {
		if ap == target {
			return true
		}
	}

	return false
}

// keyNum extracts the numeric part of a key.
// Keys are assumed to be JIRA-style in the form ALPHA-nn where 'nn'
// is an integer.  We assume that all of the keys in a given database
// have the same ALPHA value.
func keyNum(key string) int {
	m := keyRe.FindStringSubmatch(key)
	if m == nil {
		panic("Malformed key")
	}

	num, err := strconv.Atoi(m[1])
	if err != nil {
		panic(err)
	}

	return num
}

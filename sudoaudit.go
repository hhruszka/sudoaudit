package main

// go mod edit -replace github.com/zRedShift/mimemagic/v2=./mimemagic-2.0.0^C

import (
	"fmt"
	"github.com/zRedShift/mimemagic/v2"
	"os"
	"regexp"
	"strings"
)

const UserRunSection = `^User .+ may run the following commands on`
const UserRunAsEntry = `(\(.+(\:?.+)?\)){1} *(NOEXEC:)? *(NOPASSWD:)?`

func getLineWithPatternIndex(pattern string, lines []string) (int, bool) {
	reg, err := regexp.Compile(pattern)

	if err != nil {
		fmt.Printf("[!!] Compiling of %s to regular expression failed due to error: \n", pattern, err.Error())
		os.Exit(1)
	}

	for idx, line := range lines {
		if reg.Match([]byte(line)) {
			return idx, true
		}
	}

	return 0, false
}

func getLinesWithPatternIndexes(pattern string, lines []string) []int {
	var indexes []int

	reg, err := regexp.Compile(pattern)

	if err != nil {
		fmt.Printf("[!!] Compiling of %s to regular expression failed due to error: \n", pattern, err.Error())
		os.Exit(1)
	}

	for idx, line := range lines {
		if reg.Match([]byte(line)) {
			indexes = append(indexes, idx)
		}
	}

	return indexes
}

func getRunAsSudoEntries(sudo []string) []string {
	var entries []string

	if idx, ok := getLineWithPatternIndex(UserRunSection, sudo); ok {
		//fmt.Printf("Found line %d\n", idx)

		runAsSection := sudo[idx+1:]
		indexes := getLinesWithPatternIndexes(UserRunAsEntry, runAsSection)

		var entry string

		for idx := 0; idx < len(indexes); idx++ {
			if idx < len(indexes)-1 {
				entry = strings.Join(runAsSection[indexes[idx]:indexes[idx+1]], "")
			} else {
				entry = strings.Join(runAsSection[indexes[idx]:], "")
			}
			entries = append(entries, strings.TrimSpace(entry))
		}
	}

	return entries
}

func removePatternFromLines(pattern string, lines ...string) []string {
	var cleanedlines []string

	reg, err := regexp.Compile(pattern)

	if err != nil {
		fmt.Printf("[!!] Compiling of %s to regular expression failed due to error: \n", pattern, err.Error())
		os.Exit(1)
	}

	for _, line := range lines {
		if loc := reg.FindIndex([]byte(line)); loc != nil {
			cleanedlines = append(cleanedlines, line[loc[1]+1:])
		}
	}

	return cleanedlines
}

func findLinesWithPattern(pattern string, lines ...string) []string {
	var linesWithPattern []string

	reg, err := regexp.Compile(pattern)

	if err != nil {
		fmt.Printf("[!!] Compiling of %s to regular expression failed due to error: \n", pattern, err.Error())
		os.Exit(1)
	}

	for _, line := range lines {
		if reg.Match([]byte(line)) {
			linesWithPattern = append(linesWithPattern, line)
		}
	}

	return linesWithPattern
}

func getRunAsRootSudoCommands(lines []string) []string {
	var rootCommands []string
	entries := getRunAsSudoEntries(lines)

	if rootEntries := findLinesWithPattern(`^ *\((root|ALL) *(\:?.+)?\){1}`, entries...); rootEntries != nil {
		entries = removePatternFromLines(UserRunAsEntry, rootEntries...)
		for _, entry := range entries {
			entry = strings.Join(strings.Fields(entry), " ")
			for _, cmd := range strings.Split(entry, ",") {
				rootCommands = append(rootCommands, strings.TrimSpace(cmd))
			}
		}
	}

	return rootCommands
}

/*
- check if they are writable - ERROR
- check if they are readable - WARNING about potential exploitation if this is a script
- check if this is an absolute path - ERROR if not
- if the cmd is bash or any of a scripting languages then find the script and check its permissions

+ how to find out if the cmd is a linux executable and can be executed through execution PATH
+ python, bash and perl scripts detection through mime types
+ check if the cmd is on the GTFOBins list -> if it is then it is EXPLOITABLE
*/

func main() {
	// https://unix.stackexchange.com/questions/473950/sudo-disallow-shell-escapes-as-a-default

	//sudo, err := exec.Command("sudo", "-l", "-n").Output()
	//if err != nil {
	//	log.Fatal(err)
	//}
	//
	//lines := strings.Split(string(sudo), "\n")
	////for idx, line := range lines {
	////	fmt.Println(idx, ":", line)
	////}
	//
	//rootCommands := getRunAsRootSudoCommands(lines)
	//
	//for _, cmd := range rootCommands {
	//	//fmt.Println(cmd)
	//
	//	fileInfo, err := os.Stat(strings.Fields(cmd)[0])
	//	if err != nil {
	//		fmt.Printf("%s - %s\n", cmd, err.Error())
	//		continue
	//	}
	//
	//	mimeType, _ := mimemagic.MatchFilePath(cmd, -1)
	//
	//	// Get permissions in octal
	//	permissions := fileInfo.Mode().Perm()
	//	fmt.Printf("%s %s %s\n", permissions, cmd, mimeType.MediaType())
	//}

	mimeType, _ := mimemagic.MatchFilePath(os.Args[1], -1)
	fmt.Printf("%s\n", mimeType.MediaType())
}

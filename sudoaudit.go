package main

// go mod edit -replace github.com/zRedShift/mimemagic/v2=./mimemagic-2.0.0^C

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const UserRunSection = `^User .+ may run the following commands on`

// const UserRunAsEntry = `(\(.+(\:?.+)?\)){1} *(NOEXEC:)? *(NOPASSWD:)?`
const UserRunAsEntry = `(\(.+(\:?.+)?\)){1}`

var currentUser *user.User
var hostName string

// Returns index of the first line that matches the pattern and true when such a line was found,
// otherwise returns zero and false.
func getLineWithPatternIndex(pattern string, lines []string) (int, bool) {
	reg, err := regexp.Compile(pattern)

	if err != nil {
		fmt.Printf("[!!] Compiling of %s to regular expression failed due to error: %s\n", pattern, err.Error())
		os.Exit(1)
	}

	for idx, line := range lines {
		if reg.Match([]byte(line)) {
			return idx, true
		}
	}

	return 0, false
}

// Returns a table with indexes of lines that match pattern
func getLinesWithPatternIndexes(pattern string, lines []string) []int {
	var indexes []int

	reg, err := regexp.Compile(pattern)

	if err != nil {
		fmt.Printf("[!!] Compiling of %s to regular expression failed due to error: %s\n", pattern, err.Error())
		os.Exit(1)
	}

	for idx, line := range lines {
		if reg.Match([]byte(line)) {
			indexes = append(indexes, idx)
		}
	}

	return indexes
}

// This function finds all runAs lines in the output of sudo -l.
// If commands are spreading multiple lines for runAs section then they
// are collapsed into a single, comma seperated line with trimmed spaces.
// It returns a string table with each string representing one runAs section
// (e.g. (root) NOPASSWD: /bin/hack) in the output of sudo -l
func getRunAsSudoEntries(sudo []string) []string {
	var entries []string

	// Find section in the out of sudo -l where the list of runAs entries starts
	if idx, ok := getLineWithPatternIndex(UserRunSection, sudo); ok {
		//fmt.Printf("Found line %d\n", idx)

		runAsSection := sudo[idx+1:]
		// get indexes of all lines starting runAs entries
		indexes := getLinesWithPatternIndexes(UserRunAsEntry, runAsSection)

		var entry string

		// collapse in single lines all multiple lines runAs entries
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

// Removes a pattern from a single string or strings in a table
func removePatternFromLines(pattern string, lines ...string) []string {
	var cleanedlines []string

	reg, err := regexp.Compile(pattern)

	if err != nil {
		fmt.Printf("[!!] Compiling of %s to regular expression failed due to error: %s\n", pattern, err.Error())
		os.Exit(1)
	}

	for _, line := range lines {
		if loc := reg.FindIndex([]byte(line)); loc != nil {
			cleanedlines = append(cleanedlines, line[loc[1]+1:])
		}
	}

	return cleanedlines
}

func removePatternFromLine(pattern, line string) string {
	return removePatternFromLines(pattern, line)[0]
}

// Find all lines matching pattern and return them in a table
func findLinesWithPattern(pattern string, lines ...string) []string {
	var linesWithPattern []string

	reg, err := regexp.Compile(pattern)

	if err != nil {
		fmt.Printf("[!!] Compiling of %s to regular expression failed due to error: %s\n", pattern, err.Error())
		os.Exit(1)
	}

	for _, line := range lines {
		if reg.Match([]byte(line)) {
			linesWithPattern = append(linesWithPattern, line)
		}
	}

	return linesWithPattern
}

// Finds all runAs entries giving root or ALL privileges and retrieves
// commands from them. All commands are returned in a string table
func getRunAsRootSudoCommands(lines []string) (sudoCommands []*SudoRunAsCmd) {
	entries := getRunAsSudoEntries(lines)

	if rootEntries := findLinesWithPattern(`^ *\((root|ALL) *(\:?.+)?\){1}`, entries...); rootEntries != nil {

		var runAsFlags RunAsFlags

		for _, rootEntry := range rootEntries {

			// let's remove the privilege information from the line, note that runAs flags are left intact
			cleanedRootEntry := removePatternFromLine(UserRunAsEntry, rootEntry)

			// Now let's split runAs entry into separate commands based on comma separator
			commands := strings.Split(cleanedRootEntry, ",")
			for _, cmd := range commands {
				// If a command does not have runAs flags set then use the ones found earlier since they are still in power.
				cmd = strings.TrimSpace(cmd)
				//fmt.Println(cmd)
				if hasRunAsFlags(cmd) {
					runAsFlags = getRunAsFlags(cmd)
				}
				cleanedCmd := removeRunAsFlags(cmd)
				fmt.Println(cleanedCmd)
				sudoCommands = append(sudoCommands, NewSudoEntry(cleanedCmd, runAsFlags))
			}
		}
	}
	return sudoCommands
}

//func getRunAsRootSudoCommands(lines []string) (nopasswdEntries []string, noexecEntries []string, bothEntries []string, passwdEntries []string) {
//	entries := getRunAsSudoEntries(lines)
//
//	// Find all root or ALL runAs lines
//	if rootEntries := findLinesWithPattern(`^ *\((root|ALL) *(\:?.+)?\){1}`, entries...); rootEntries != nil {
//		//entries = removePatternFromLines(UserRunAsEntry, rootEntries...)
//		for _, rootEntry := range rootEntries {
//			var rootCommands []string
//			entry := removePatternFromLines(UserRunAsEntry, rootEntry)[0]
//			entry = strings.Join(strings.Fields(entry), " ")
//			for _, cmd := range strings.Split(entry, ",") {
//				rootCommands = append(rootCommands, strings.TrimSpace(cmd))
//			}
//
//			if strings.Contains(rootEntry, "NOPASS") && strings.Contains(rootEntry, "NOEXEC") {
//				bothEntries = append(bothEntries, rootCommands...)
//			} else if strings.Contains(rootEntry, "NOEXEC") {
//				noexecEntries = append(noexecEntries, rootCommands...)
//			} else if strings.Contains(rootEntry, "NOPASS") {
//				nopasswdEntries = append(nopasswdEntries, rootCommands...)
//			} else {
//				passwdEntries = append(nopasswdEntries, rootCommands...)
//			}
//		}
//		for _, entry := range entries {
//			entry = strings.Join(strings.Fields(entry), " ")
//			for _, cmd := range strings.Split(entry, ",") {
//				rootCommands = append(rootCommands, strings.TrimSpace(cmd))
//			}
//		}
//	}
//
//	return
//}

/*
- check if they are pathIsWritable - ERROR
- check if they are pathIsReadable - WARNING about potential exploitation if this is a script
- check if this is an absolute path - ERROR if not
- if a cmd is bash or any of a scripting languages, then find the script and check its permissions

+ how to find out if the cmd is a linux executable and can be executed through execution PATH
+ python, bash and perl scripts detection through mime types
+ check if the cmd is on the GTFOBins list -> if it is then it is EXPLOITABLE
*/

func init() {
	var err error
	currentUser, err = user.Current()
	if err != nil {
		fmt.Printf("[!!] Failed to determine a user who is running %s application. Aborting!\n", os.Args[0])
		os.Exit(1)
	}

	hostName, err = os.Hostname()
	if err != nil {
		fmt.Println("[!!] Failed to obtain a hostname. Aborting!\n")
		os.Exit(1)
	}
}

func main() {
	// https://unix.stackexchange.com/questions/473950/sudo-disallow-shell-escapes-as-a-default
	var manualAnalysisNeeded []*SudoRunAsCmd
	var knownExploitableBinaries []*SudoRunAsCmd
	var exploitableExecutables []*SudoRunAsCmd

	fmt.Printf("[+] Starting application: %s\n", filepath.Base(os.Args[0]))

	sudo, err := exec.Command("sudo", "-l", "-n").Output()
	if err != nil {
		fmt.Printf("[-] Failed to execute 'sudo -l' without password.\n")
		//log.Fatalf("Execution of 'sudo -l' failed with error: %s\n", err.Error())
		fmt.Printf("[*] Please provide password: ")
		password, err := terminal.ReadPassword(0)
		if err != nil {
			fmt.Println("[-] Failed to read password:", err)
			return
		}
		fmt.Println()
		cmd := exec.Command("sudo", "-S", "-l")

		// Create a bytes.Buffer and write the password to it, followed by a newline
		var stdinBuf bytes.Buffer
		stdinBuf.Write(password)
		stdinBuf.WriteByte('\n')

		// Set the stdin of the command to the buffer
		cmd.Stdin = &stdinBuf

		// Run the command and capture stdout and stderr
		sudo, err = cmd.Output()
		if err != nil {
			fmt.Println("[-] Failed to run sudo -l with password: ", err)
			return
		}
	}
	lines := strings.Split(string(sudo), "\n")

	sudoCommands := getRunAsRootSudoCommands(lines)

	fmt.Println("\n\t\t\tAUDIT RESULTS:\n\n")
	fmt.Printf("Date: %s\n", time.Now().Format(time.DateTime))
	fmt.Printf("Host: %s\n", hostName)
	fmt.Printf("User: %s\n\n", currentUser.Username)
	fmt.Println()
	fmt.Printf("Found %d command(s) that can be executed with root privileges via sudo\n\n", len(sudoCommands))

	for _, sudoCmd := range sudoCommands {
		if sudoCmd.command == "" {
			manualAnalysisNeeded = append(manualAnalysisNeeded, sudoCmd)
			continue
		}

		if sudoCmd.command == "ALL" {
			fmt.Printf("[!!] CRITICAL! sudo has been configured to allow %s user to run ALL executables/commands on the %s host with root prvileges\n", currentUser.Username, hostName)
			//continue
		}

		if sudoCmd.DoesFileExist() && IsListed(sudoCmd.command, exploitableSudoBinaries) {
			knownExploitableBinaries = append(knownExploitableBinaries, sudoCmd)
		}

		// Checking ownership is not needed here since a user can modify a file
		if sudoCmd.DoesFileExist() && sudoCmd.IsFileWritable() {
			exploitableExecutables = append(exploitableExecutables, sudoCmd)
		}

		// Checking ownership is not needed here since a user can create or replace a file in a directory
		// also regardless whether a file exists
		if sudoCmd.IsDirWritable() {
			exploitableExecutables = append(exploitableExecutables, sudoCmd)
		}
	}

	if len(knownExploitableBinaries) > 0 {
		fmt.Printf("[+] Found %d known exploitable executables:\n", len(knownExploitableBinaries))
		for _, cmd := range knownExploitableBinaries {
			fmt.Printf("%s\n", cmd)
		}
	}

	if len(exploitableExecutables) > 0 {
		fmt.Printf("[+] Found %d exploitable executables:\n", len(exploitableExecutables))
		for _, cmd := range exploitableExecutables {
			fmt.Printf("%s\n", cmd)
		}
	}

	if len(manualAnalysisNeeded) > 0 {
		fmt.Printf("[+] %d found commands requires manual analysis:\n", len(manualAnalysisNeeded))
		for _, cmd := range manualAnalysisNeeded {
			fmt.Printf("%s\n", cmd)
		}
	}
}

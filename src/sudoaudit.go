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
	"sort"
	"strings"
	"time"
)

const UserRunSection = `^User .+ may run the following commands on`

// const UserRunAsEntry = `(\(.+(\:?.+)?\)){1} *(NOEXEC:)? *(NOPASSWD:)?`
const UserRunAsEntry = `(\(.+(\:?.+)?\)){1}`

var boolMap map[bool]string = map[bool]string{false: "no", true: "yes"}
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

				if hasRunAsFlags(cmd) {
					runAsFlags = getRunAsFlags(cmd)
				}
				cleanedCmd := removeRunAsFlags(cmd)
				sudoCommands = append(sudoCommands, NewSudoEntry(cleanedCmd, runAsFlags))
			}
		}
	}
	return sudoCommands
}

func init() {
	var err error

	fmt.Printf("[*] Starting application: %s\n", filepath.Base(os.Args[0]))

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

func GetSudoCommands() []string {
	sudo, err := exec.Command("sudo", "-l", "-n").Output()

	// sudo -l requires a password
	if err != nil {
		fmt.Printf("[-] Failed to execute 'sudo -l' without password.\n")
		fmt.Printf("[*] Please provide password: ")
		password, err := terminal.ReadPassword(0)

		if err != nil {
			fmt.Println("[-] Failed to read password:", err)
			os.Exit(1)
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
			os.Exit(1)
		}
	}

	// get output from 'sudo -l', find all commands that can be run as root and analyze them
	return strings.Split(string(sudo), "\n")
}

// GetAllSudoCommands returns list of all sudo runAs commands (with parameters/options they will be invoked with)
func GetAllSudoCommands(sudoCommands []*SudoRunAsCmd) []string {
	var list []string

	for _, sudoCmd := range sudoCommands {
		list = append(list, sudoCmd.fullCommand)
	}
	sort.Strings(list)
	return list
}

// GetAllExecutablesWithTheirPermissions returns list of all unique executables with their permissions.
func GetAllExecutablesWithTheirPermissions(sudoCommands []*SudoRunAsCmd) ([]string, map[string]string) {
	var dict map[string]string = make(map[string]string)

	for _, sudoCmd := range sudoCommands {
		// collect all executables with their permissions, also remove duplicates -
		if sudoCmd.command != "" {
			if _, ok := dict[sudoCmd.command]; !ok && sudoCmd.pathExists {
				dict[sudoCmd.command] = sudoCmd.printFileInfo()
			}
		}
	}

	keys := make([]string, 0, len(dict))

	// collect keys
	for k := range dict {
		keys = append(keys, k)
	}

	// sort keys
	sort.Strings(keys)

	return keys, dict
}

// GetAllNotFoundExecutables returns sorted keys and corresponding map of not found executables
func GetAllNotFoundExecutables(sudoCommands []*SudoRunAsCmd) ([]string, map[string]string) {
	var dict map[string]string = make(map[string]string)

	for _, sudoCmd := range sudoCommands {
		// collect all executables with their permissions, also remove duplicates -> that's why map is used.
		if sudoCmd.command != "" && sudoCmd.command != "ALL" {
			if _, ok := dict[sudoCmd.command]; !ok && !sudoCmd.pathExists {
				dict[sudoCmd.command] = sudoCmd.fullCommand
			}
		}
	}

	keys := make([]string, 0, len(dict))

	// collect keys
	for k := range dict {
		keys = append(keys, k)
	}

	// sort keys
	sort.Strings(keys)

	return keys, dict
}

// GetCommandsWithWritableParentDirs returns list of sudo commands that have writable parent directories.
// Parent directory of an executable is writable, which allows to replace the executable with a malicious copy.
// REMARK:
// Checking ownership is not needed since a user can create or replace a file in a directory
// also regardless whether a file exists.
func GetCommandsWithWritableParentDirs(sudoCommands []*SudoRunAsCmd) (writableParentDirExecutables []*SudoRunAsCmd) {
	for _, sudoCmd := range sudoCommands {
		if sudoCmd.command != "" {
			if sudoCmd.IsDirWritable() && sudoCmd.DoesDirExist() {
				writableParentDirExecutables = append(writableParentDirExecutables, sudoCmd)
			}
		}
	}
	return writableParentDirExecutables
}

// GetCommandsWithWritableExecutables returns list of sudo runAs commands that have writable executables.
// Executable (binary or script) is writable thus vulnerable since it can be changed to get root
// REMARK:
// Checking ownership is not needed here since a user can modify a file
func GetCommandsWithWritableExecutables(sudoCommands []*SudoRunAsCmd) (writableExecutables []*SudoRunAsCmd) {
	for _, sudoCmd := range sudoCommands {
		if sudoCmd.command != "" {
			if sudoCmd.DoesFileExist() && sudoCmd.IsFileWritable() {
				writableExecutables = append(writableExecutables, sudoCmd)
			}
		}
	}
	return writableExecutables
}

// GetCommandsWithKnownExploitableExecutables returns list of sudo runAs commands that have an executables that
// is known to be exploitable when run with sudo - is present on the GTFOBins sudo executables.
func GetCommandsWithKnownExploitableExecutables(sudoCommands []*SudoRunAsCmd) (knownExploitableExecutable []*SudoRunAsCmd) {
	for _, sudoCmd := range sudoCommands {
		if sudoCmd.command != "" {
			// file exists and is known exploitable binary per GTFOBins
			if sudoCmd.DoesFileExist() && IsListed(sudoCmd.command, exploitableSudoBinaries) {
				knownExploitableExecutable = append(knownExploitableExecutable, sudoCmd)
			}
		}
	}
	return knownExploitableExecutable
}

// IsALLPresent returns true when it finds ALL literal on the list of sudo runAs commands.
func IsALLPresent(sudoCommands []*SudoRunAsCmd) bool {
	for _, sudoCmd := range sudoCommands {
		// this is the worst case if user can run ALL commands as root
		if sudoCmd.command == "ALL" {
			return true
		}
	}
	return false
}

// GetCommandsForManualAnalysis returns list of sudo runAs commands that have to be analyzed manually, because the
// executable could not be derived automatically.
func GetCommandsForManualAnalysis(sudoCommands []*SudoRunAsCmd) (manualAnalysisNeeded []*SudoRunAsCmd) {
	for _, sudoCmd := range sudoCommands {
		if sudoCmd.command == "" {
			manualAnalysisNeeded = append(manualAnalysisNeeded, sudoCmd)
		}
	}
	return manualAnalysisNeeded
}

// printCmdInfo prints sudo cmd details to bufferedPrintout buffer
func printCmdInfo(bufferedPrintout *bytes.Buffer, cmd *SudoRunAsCmd) {
	_, _ = fmt.Fprintf(bufferedPrintout, "Sudo command: %s\n", cmd.fullCommand)
	_, _ = fmt.Fprintf(bufferedPrintout, "Vulnerable executable: %s\n", cmd.command)
	_, _ = fmt.Fprintf(bufferedPrintout, "RunAs flags: %s\n", strings.Join(cmd.getRunAsFlags(), " "))
	_, _ = fmt.Fprintf(bufferedPrintout, "Permissions: %s\n", cmd.printFileInfo())
	_, _ = fmt.Fprintf(bufferedPrintout, "Executable exists or is accessible: %s\n", boolMap[cmd.pathExists])
	if cmd.pathExists {
		_, _ = fmt.Fprintf(bufferedPrintout, "Executable is writable: %s\n", boolMap[cmd.pathIsWritable])
	}
	_, _ = fmt.Fprintf(bufferedPrintout, "Parent director exists or is accessible: %s\n", boolMap[cmd.parentDirExists])
	if cmd.parentDirExists {
		_, _ = fmt.Fprintf(bufferedPrintout, "Parent director is writable: %s\n", boolMap[cmd.parentDirWritable])
	}
}

// PrepReportHeader prepares header of a report and writes it to bufferedPrintout
func PrepReportHeader(bufferedPrintout *bytes.Buffer, sudoCommands []*SudoRunAsCmd) {
	_, _ = fmt.Fprintf(bufferedPrintout, "\n\t\t\tSUDO AUDIT RESULTS:\n\n")
	_, _ = fmt.Fprintf(bufferedPrintout, "Date: %s\n", time.Now().Format(time.DateTime))
	_, _ = fmt.Fprintf(bufferedPrintout, "Host: %s\n", hostName)
	_, _ = fmt.Fprintf(bufferedPrintout, "User: %s\n\n", currentUser.Username)
	_, _ = fmt.Fprintln(bufferedPrintout)
	_, _ = fmt.Fprintf(bufferedPrintout, "Found %d command(s) that can be executed with root privileges via sudo\n\n", len(sudoCommands))
}

// GenReport prepares body of a report and writes it to bufferedPrintout
func GenReport(bufferedPrintout *bytes.Buffer, sudoCommands []*SudoRunAsCmd) {
	if IsALLPresent(sudoCommands) {
		_, _ = fmt.Fprintf(bufferedPrintout, "\n[!!] CRITICAL! sudo has been configured to allow %s user to run ALL executables/commands on the %s host with root prvileges\n", currentUser.Username, hostName)
	}

	section := 1
	_, _ = fmt.Fprintf(bufferedPrintout, "\n[SECTION %d] List of sudo commands (executables with options/parameters):\n", section)
	allSudoRunAsCommands := GetAllSudoCommands(sudoCommands)
	if len(allSudoRunAsCommands) > 0 {
		for _, sudoCmd := range allSudoRunAsCommands {
			_, _ = fmt.Fprintf(bufferedPrintout, "%s\n", sudoCmd)
		}
	} else {
		_, _ = fmt.Fprintf(bufferedPrintout, "Found no sudo entries that can be executed/run as root!\n")
		os.Exit(0)
	}

	section++
	_, _ = fmt.Fprintf(bufferedPrintout, "\n[SECTION %d] List of existing sudo executables (sorted and unique):\n", section)
	keys, commandPermList := GetAllExecutablesWithTheirPermissions(sudoCommands)
	if len(commandPermList) > 0 {
		for _, key := range keys {
			_, _ = fmt.Fprintf(bufferedPrintout, "%s\n", commandPermList[key])
		}

	} else {
		_, _ = fmt.Fprintf(bufferedPrintout, "Could not derive any existing executables from sudo entries.\n")
	}

	section++
	_, _ = fmt.Fprintf(bufferedPrintout, "\n[SECTION %d] List of sudo commands with not found (not existing or not accessible) executables (sorted and unique):\n", section)
	keys, notFoundCommandList := GetAllNotFoundExecutables(sudoCommands)
	if len(notFoundCommandList) > 0 {
		for _, key := range keys {
			_, _ = fmt.Fprintf(bufferedPrintout, "%s\n", notFoundCommandList[key])
		}

	} else {
		_, _ = fmt.Fprintf(bufferedPrintout, "No \"not found\" executables.\n")
	}

	section++
	_, _ = fmt.Fprintf(bufferedPrintout, "\n[SECTION %d] Executables that are known to be exploitable per GTFOBins. Check GTFOBins to get detailed information about potential exploitation methods.\n", section)
	knownExploitableExecutable := GetCommandsWithKnownExploitableExecutables(sudoCommands)
	if len(knownExploitableExecutable) > 0 {
		for _, cmd := range knownExploitableExecutable {
			_, _ = fmt.Fprintln(bufferedPrintout)
			printCmdInfo(bufferedPrintout, cmd)
		}
	} else {
		_, _ = fmt.Fprintf(bufferedPrintout, "Found no executables that are known to be exploitable!\n")
	}

	section++
	_, _ = fmt.Fprintf(bufferedPrintout, "\n[SECTION %d] List of writable executables:\n", section)
	writableExecutables := GetCommandsWithWritableExecutables(sudoCommands)
	if len(writableExecutables) > 0 {
		for _, cmd := range writableExecutables {
			_, _ = fmt.Fprintln(bufferedPrintout)
			printCmdInfo(bufferedPrintout, cmd)
		}
	} else {
		_, _ = fmt.Fprintf(bufferedPrintout, "Found no writable executables!\n")
	}

	section++
	_, _ = fmt.Fprintf(bufferedPrintout, "\n[SECTION %d] List of executables (existing and non-existing) that parent directories are writable:\n", section)
	writableParentDirExecutables := GetCommandsWithWritableParentDirs(sudoCommands)
	if len(writableParentDirExecutables) > 0 {
		//_, _ = fmt.Fprintf(bufferedPrintout, "\n[SECTION 4] Found %d exploitable executables:\n", len(exploitableExecutables))
		for _, cmd := range writableParentDirExecutables {
			_, _ = fmt.Fprintln(bufferedPrintout)
			printCmdInfo(bufferedPrintout, cmd)
		}
	} else {
		_, _ = fmt.Fprintf(bufferedPrintout, "Found no writable parent directories of executables!\n")
	}

	section++
	_, _ = fmt.Fprintf(bufferedPrintout, "\n[SECTION %d] List of sudo runAs commands that require manual analysis:\n", section)
	manualAnalysisNeeded := GetCommandsForManualAnalysis(sudoCommands)
	if len(manualAnalysisNeeded) > 0 {
		for _, cmd := range manualAnalysisNeeded {
			_, _ = fmt.Fprintln(bufferedPrintout)
			printCmdInfo(bufferedPrintout, cmd)
		}
	} else {
		_, _ = fmt.Fprintf(bufferedPrintout, "No sudo commands require manual analysis!\n")
	}

}

func main() {
	sudoRunAsLines := GetSudoCommands()
	sudoCommands := getRunAsRootSudoCommands(sudoRunAsLines)

	var bufferedPrintout *bytes.Buffer = &bytes.Buffer{}

	PrepReportHeader(bufferedPrintout, sudoCommands)
	GenReport(bufferedPrintout, sudoCommands)
	fmt.Printf("%s", bufferedPrintout.String())
}

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type SudoFlags uint8

const (
	PASSWD SudoFlags = 1 << iota
	NOPASSWD
	EXEC
	NOEXEC
)

type SudoRunAsCmd struct {
	fullCommand   string         // full commands with any options etc.
	command       string         // only command: binary or script
	commandType   ExecutableType // is it an elf binary or shell script or python scrit or perl script or java
	absolutePath  bool
	parentDirStat fs.FileInfo
	commandStat   fs.FileInfo
	writable      bool
	readable      bool
	ownerUid      int
	groupUid      int
	sudoFlags     uint8
}

func (cmd *SudoRunAsCmd) Exists() bool {
	return cmd.commandStat != nil
}

func (cmd *SudoRunAsCmd) IsWritable() bool {
	return cmd.writable
}

func (cmd *SudoRunAsCmd) IsReadable() bool {
	return cmd.readable
}

func (cmd *SudoRunAsCmd) getFlags(fullCommand string) SudoFlags {
	return PASSWD
}

func removeRunAsFlags(command string) string {
	return removePatternFromLines(` *([A-Z]+: +)*`, command)[0]
}

// This function creates SudoRunAsCmd, which is a single command from a runAs line in sudo -l output.
// fullCmd parameter is a cleaned command, which means that sudo flags (e.g. NOPASSWD or NOEXEC) has been removed.
func NewSudoEntry(fullcmd string, sudoFlags uint8) *SudoRunAsCmd {
	var cmd SudoRunAsCmd = SudoRunAsCmd{}
	var err error

	cmd.fullCommand = fullcmd
	cmd.sudoFlags = sudoFlags
	if cmd.command, err = getCommand(fullcmd); err != nil {
		fmt.Printf("Internal program error in function %s: %s", getCurrentFunctionName(), err.Error())
		os.Exit(1)
	}

	if cmd.command != "" {
		// at this point cmd.command contains a filepath but we do not know if it is a patch to an existing file
		if DoesFileExist(cmd.command) {

		}
	}
	return &cmd
}

func getCommand(fullCommand string) (string, error) {

	splitCommand := strings.Fields(fullCommand)

	// split failed because string was empty, it should not happen.
	if len(splitCommand) == 0 {
		return "", errors.New("Passed command string was empty.")
	}

	// there is a single command specified in a string which means that this is actual command
	if len(splitCommand) == 1 {
		return fullCommand, nil
	}

	// If we got here then it means that we have multiple tokens in fullCommand
	// Check if a first token is an interpreter, it is not than we have a command with options,
	// and we do not have to look for anything else at this point
	baseCommand := splitCommand[0]
	if !IsListed(baseCommand, Interpreters) {
		return baseCommand, nil
	}

	// If we got here then it means that one of a script interpreters got detected,
	// and we need to find the actual script that will be executed.

	// First check the first token passed to the script. If it does not contain '-' then it has to be assumed a script.
	if !strings.Contains(splitCommand[1], `-`) {
		return splitCommand[1], nil
	}

	// The first token turned out to be an option since it contained '-'.
	// Now, let's do scripting language specific analysis
	switch filepath.Base(baseCommand) {
	case `bash`:
		fallthrough
	case `sh`:
		fallthrough
	case `ksh`:
		fallthrough
	case `dash`:
		fallthrough
	case `zsh`:
		fallthrough
	case `fish`:
		fallthrough
	case `csh`:
		fallthrough
	case `tcsh`:
		fallthrough
	case `rbash`:
		fallthrough
	case `rksh`:
		fallthrough
	case `rzsh`:
		fallthrough
	case `wsh`:
		return findPotentialFile(fullCommand), nil
	case `perl`:
		fallthrough
	case `perl5`:
		if strings.Contains(fullCommand, "-e") {
			return "", nil
		}
		if strings.Contains(fullCommand, "-E") {
			return "", nil
		}
		if strings.Contains(fullCommand, "-S") {
			return "", nil
		}
		return findPotentialFile(fullCommand), nil
	case `python`:
		fallthrough
	case `python2`:
		fallthrough
	case `python3`:
		// options -c and -m are terminating, it means that any script has not been passed, and the whole command has to be analyzed manually.
		if strings.Contains(fullCommand, `-c`) {
			return "", nil
		}

		if strings.Contains(fullCommand, `-m`) {
			return "", nil
		}

		// Here we split a command line into tokens and test whether any of them is a potential file.
		// It is done using filepath.IsAbs() function that checks if a string is an absolute path.
		// We do not test for a file existance since it will be done later.
		// If no token has been found that is an absolute path then the function returns empty string and nil.
		return findPotentialFile(fullCommand), nil
	case `java`:
		// java programs can be run as classes with options -cp -classpath and it requires manual analysis,
		// however they can also be run as java archives (jar files). In such cases they are run by -jar option.ccccccrjicivjhtfcgiubrgtcibvnergcncnengdtjtk

		if strings.Contains(fullCommand, `-jar`) {
			for idx, token := range splitCommand {
				if token == "-jar" {
					if idx < len(splitCommand) && filepath.IsAbs(splitCommand[idx+1]) {
						return splitCommand[idx+1], nil
					}
				}
			}
		}
		return "", nil
	case `ruby`:
		return findPotentialFile(fullCommand), nil
	default:
		return "", errors.New("command has not been recognized!")
	}
}

func AnalyzeCommands(commands []string) error {
	return nil
}

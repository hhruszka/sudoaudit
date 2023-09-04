//go:build linux

package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

type RunAsFlags uint8

const (
	PASSWD RunAsFlags = 1 << iota
	NOPASSWD
	EXEC
	NOEXEC
)

var sudoMapping map[string]RunAsFlags = map[string]RunAsFlags{"PASSWD:": PASSWD, "NOPASSWD:": NOPASSWD, "EXEC:": EXEC, "NOEXEC:": NOEXEC}

type SudoRunAsCmd struct {
	fullCommand       string   // full commands with any options etc.
	command           string   // only command: binary or script
	pathType          PathType // is it an elf binary or shell script or python scrit or perl script or java
	pathIsAbsolute    bool
	parentDirStat     os.FileInfo
	pathStat          os.FileInfo
	pathExists        bool
	pathIsWritable    bool
	pathIsReadable    bool
	parentDirExists   bool
	parentDirWritable bool
	parentDirReadable bool
	ownerInfo         *user.User
	groupInfo         *user.Group
	runAsFlags        RunAsFlags
}

func (cmd *SudoRunAsCmd) DoesFileExist() bool {
	return cmd.pathExists
}

func (cmd *SudoRunAsCmd) DoesDirExist() bool {
	return cmd.parentDirExists
}

func (cmd *SudoRunAsCmd) IsFileWritable() bool {
	return cmd.pathIsWritable
}

func (cmd *SudoRunAsCmd) IsFileReadable() bool {
	return cmd.pathIsReadable
}

func (cmd *SudoRunAsCmd) getFlags(fullCommand string) RunAsFlags {
	return cmd.runAsFlags
}

func (cmd *SudoRunAsCmd) IsDirReadable() bool {
	return cmd.parentDirReadable
}

func (cmd *SudoRunAsCmd) IsDirWritable() bool {
	return cmd.parentDirWritable
}

func (cmd *SudoRunAsCmd) CanUserModifyFile() bool {
	currentUser, _ := user.Current()
	return cmd.pathIsWritable || (cmd.ownerInfo.Uid == currentUser.Uid)
}

func (cmd *SudoRunAsCmd) CanUserReplaceFile() bool {
	return cmd.parentDirWritable
}

func (cmd *SudoRunAsCmd) printInfo() {
	// Mimic `ls -l` format: permissions, owner, group, filename
	if cmd.command != "" {
		if cmd.pathExists == true {
			fmt.Printf("%v %v %v %v\n", cmd.pathStat.Mode().Perm(), cmd.ownerInfo.Username, cmd.groupInfo.Name, cmd.command)
		} else {
			fmt.Printf("%v\n", cmd.command)
		}
	} else {
		fmt.Println(cmd.fullCommand)
	}
}

// This function creates SudoRunAsCmd, which is a single command from a runAs line in sudo -l output.
// fullCmd parameter is a cleaned command, which means that sudo flags (e.g. NOPASSWD or NOEXEC) has been removed.
func NewSudoEntry(fullCmd string, sudoFlags RunAsFlags) *SudoRunAsCmd {
	var cmd SudoRunAsCmd = SudoRunAsCmd{}
	var err error

	cmd.fullCommand = fullCmd
	cmd.runAsFlags = sudoFlags
	if cmd.command, err = getCommand(fullCmd); err != nil {
		fmt.Printf("Internal program error in function %s: %s", getCurrentFunctionName(), err.Error())
		os.Exit(1)
	}

	if cmd.command == "" {
		// it was not possible to determine the executable. This particular command will have to be reviewed manually.
		return &cmd
	}

	// at this point cmd.command contains a filepath, but we do not know if it is a path to an existing file.
	if DoesPathExist(cmd.command) {
		cmd.pathExists = true
		cmd.pathIsAbsolute = filepath.IsAbs(cmd.command)
		cmd.pathType = identifyPathType(cmd.command)
		cmd.pathIsReadable = IsReadable(cmd.command)
		cmd.pathIsWritable = IsWritable(cmd.command)
		cmd.pathStat, _ = os.Stat(cmd.command)
		cmd.parentDirStat, _ = os.Stat(filepath.Dir(cmd.command))

		if sysInfo, ok := cmd.pathStat.Sys().(*syscall.Stat_t); ok {
			userId := int(sysInfo.Uid)
			groupId := int(sysInfo.Gid)

			cmd.ownerInfo, err = user.LookupId(strconv.Itoa(userId))
			if err != nil {
				fmt.Println("Error:", err)
			}
			cmd.groupInfo, err = user.LookupGroupId(strconv.Itoa(groupId))
			if err != nil {
				fmt.Println("Error:", err)
			}
		}
	} else {
		// It might be a good sign since we just might not have permissions to access the file.
		// However, it might turn out that the file has not been created, and we could exploit that if
		// we could write to a parent directory.
		// Let see if its parent directory is accessible for us .
		if cmd.parentDirStat, err = os.Stat(filepath.Dir(cmd.command)); err != nil {
			cmd.parentDirStat = nil
			if os.IsNotExist(err) {
				// this error is a bit tricky since the directory might still exist but its parent
				// directory is not readable for us.
				cmd.parentDirExists = false
			}
			if os.IsPermission(err) {
				// this is error is clear - we do not have permissions to read content of this directory.
				cmd.parentDirExists = true
				cmd.parentDirReadable = false
			}
		} else {
			// it might be possible to exploit this command if we have permissions to write to the parent directory.
			cmd.parentDirExists = true
			cmd.parentDirReadable = IsAccessible(filepath.Dir(cmd.command))
			cmd.parentDirWritable = IsDirWritable(filepath.Dir(cmd.command))
		}
	}

	return &cmd
}

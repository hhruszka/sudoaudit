package main

import (
	"fmt"
	"github.com/zRedShift/mimemagic/v2"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

func IsListed(file string, list []string) bool {
	found := false
	for _, entry := range list {
		if file == filepath.Base(entry) {
			found = true
			break
		}
	}

	return found
}

func IsWritable(path string) bool {
	var fs os.FileInfo
	var err error

	if fs, err = os.Stat(path); err != nil {
		return false
	}
	if fs.IsDir() {
		return IsDirWritable(path)
	}
	if IsDirWritable(filepath.Dir(path)) {
		// file can be replaced irrespective of ownership and permissions by a current user
		return true
	}
	if fh, err := os.OpenFile(path, os.O_RDWR, 0); err == nil {
		// file can be modified by a current user
		_ = fh.Close()
		return true
	}
	return false
}

func IsReadable(path string) bool {
	if fh, err := os.OpenFile(path, os.O_RDONLY, 0); err == nil {
		_ = fh.Close()
		return true
	}
	return false
}

func isExecutableOnPath(executableName string) (string, bool) {
	path := os.Getenv("PATH")
	pathDirs := strings.Split(path, string(os.PathListSeparator))

	for _, dir := range pathDirs {
		exePath := filepath.Join(dir, executableName)
		_, err := os.Stat(exePath)
		if err == nil {
			return exePath, true
		}
	}

	return "", false
}

type PathType int

const (
	Binary PathType = iota
	Java
	ShellScript
	Python
	Perl
	Ruby
	Directory
	Other
)

var MimeTypeMapping map[string]PathType = map[string]PathType{"application/x-pie-executable": Binary, "application/x-executable": Binary, "application/x-perl": Perl, "text/x-python": Python, "text/x-python3": Python, "application/x-python-code": Python, "text/x-ruby": Ruby, "application/x-ruby": Ruby, "application/x-shellscript": ShellScript, "application/x-java-archive": Java, "inode/directory": Directory}

func identifyPathType(path string) PathType {
	// mimemagic does not recognize non-readable directories as directories, therefore this plug helps to fix it.
	if ok, _ := IsDirectory(path); ok {
		return Directory
	}
	mimeType, _ := mimemagic.MatchFilePath(path, -1)
	if value, ok := MimeTypeMapping[mimeType.MediaType()]; ok {
		return value
	}
	return Other
}

func IsPythonScript(file string) bool {
	mimeType, _ := mimemagic.MatchFilePath(file, -1)
	return IsListed(mimeType.MediaType(), []string{"text/x-python", "text/x-python3"})
}

func IsShellScript(file string) bool {
	mimeType, _ := mimemagic.MatchFilePath(file, -1)
	return IsListed(mimeType.MediaType(), []string{"application/x-shellscript"})
}

func IsPerlScript(file string) bool {
	mimeType, _ := mimemagic.MatchFilePath(file, -1)
	return IsListed(mimeType.MediaType(), []string{"application/x-perl"})
}

func IsScript(file string) (bool, error) {
	mimeType, err := mimemagic.MatchFilePath(file, -1)
	if err != nil {
		return false, err
	} else {
		_, found := MimeTypeMapping[mimeType.MediaType()]
		return found, nil
	}
}

// IsFile checks if the given path points to a file.
func IsFile(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.Mode().IsRegular(), nil
}

func IsDirectory(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.Mode().IsDir(), nil
}

// IsAccessible checks if the given path is accessible.
func IsAccessible(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	_ = file.Close()
	return true
}

// IsDirWritable checks whether the parent directory of a command is pathIsWritable. os.CreateTemp() is used to account
// for any ACLs set for the directory that might impact user's permissions.
func IsDirWritable(dir string) bool {
	// Create a temporary file in the directory
	tempFile, err := os.CreateTemp(dir, "testwrite")
	if err != nil {
		return false
	}

	// Remove the temporary file
	_ = os.Remove(tempFile.Name())

	return true
}

func DoesPathExist(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil
}

func getCurrentFunctionName() string {
	pc, _, _, _ := runtime.Caller(1)
	funcName := runtime.FuncForPC(pc).Name()
	return funcName
}

func findPotentialFile(line string) (filePath string) {
	tokens := strings.Fields(line)

	for _, token := range tokens {
		if filepath.IsAbs(token) {
			filePath = token
			break
		}
	}

	return filePath
}

func IsExecuteable(file any) bool {
	var fileInfo fs.FileInfo

	if path, ok := file.(string); ok {
		fileInfo, _ = os.Stat(path)
	} else {
		if fileInfo, ok = file.(fs.FileInfo); !ok {
			fmt.Printf("Internal error: function provided with unsupported type of a parameter %T. Aborting\n", file)
			os.Exit(1)
		}
	}

	fileStat := fileInfo.Sys().(*syscall.Stat_t)

	userInfo, _ := user.Current()
	uid, _ := strconv.Atoi(userInfo.Uid)
	gids, _ := syscall.Getgroups()

	// Check if the user is the owner of the file
	if uid == int(fileStat.Uid) {
		return fileInfo.Mode().Perm()&0100 != 0
	}

	// Check if the user is in any of the same groups as the file
	for _, gid := range gids {
		if gid == int(fileStat.Gid) {
			return fileInfo.Mode().Perm()&0010 != 0
		}
	}

	// Otherwise, check 'others' permissions
	return fileInfo.Mode().Perm()&0001 != 0
}

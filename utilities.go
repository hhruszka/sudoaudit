package main

import (
	"github.com/zRedShift/mimemagic/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
	if fh, err := os.OpenFile(path, os.O_RDWR, 0); err == nil {
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

type ExecutableType int

const (
	Binary ExecutableType = iota
	Java
	ShellScript
	Python
	Perl
	Ruby
	Other
)

var MimeTypeMapping map[string]ExecutableType = map[string]ExecutableType{"application/x-perl": Perl, "text/x-python": Python, "text/x-python3": Python, "application/x-python-code": Python, "text/x-ruby": Ruby, "application/x-ruby": Ruby, "application/x-shellscript": ShellScript}

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

// IsAccessible checks if the given path is accessible.
func IsAccessible(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	file.Close()
	return true, nil
}

func DoesFileExist(path string) bool {
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

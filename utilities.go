package main

import (
	"github.com/zRedShift/mimemagic/v2"
	"os"
	"path/filepath"
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

func IsScript(file string) bool {
	mimeType, _ := mimemagic.MatchFilePath(file, -1)
	return IsListed(mimeType.MediaType(), []string{"application/x-perl", "text/x-python", "text/x-python3", "application/x-shellscript"})
}

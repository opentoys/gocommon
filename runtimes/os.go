package runtimes

import (
	"os"
	"path/filepath"
)

// FileJoin
//
//	base: "a/b/c/" file: "d.txt" => "a/b/c/d.txt"
//	base: "a/b/c/" file: "/d.txt" => "/d.txt"
//	base: "a/b/c/" file: "/a/d.txt" => "/a/d.txt"
//	base: "a/b/c/e.txt" file: "d.txt" => "a/b/c/d.txt"
//	base: "/a/b/c/e.txt" file: "d.txt" => "/a/b/c/d.txt"
//	base: "/a/b/c/e.txt" file: "d" => "/a/b/c/d"
//	base: not exeits file: "d.txt" => ""
func FileJoin(base, file string) string {
	if filepath.IsAbs(file) {
		return file
	}
	s, e := os.Stat(base)
	if e != nil {
		return ""
	}
	if s.IsDir() {
		return filepath.Join(base, file)
	}
	return filepath.Join(filepath.Dir(base), file)
}

func Exist(path string) bool {
	_, e := os.Stat(path)
	return !os.IsNotExist(e)
}

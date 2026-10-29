package utils

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

func TestIsGzip(t *testing.T) {
	var tests = []struct {
		in   string
		want bool
	}{
		{filepath.Join("testdata", "test.txt.gz"), true},
		{filepath.Join("testdata", "test.tar.gz"), true},
		{filepath.Join("testdata", "test.txt"), false},
		{filepath.Join("testdata", "test.txt.zst"), false},
		{filepath.Join("testdata", "aqua.png"), false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			f, err := os.Open(tt.in)
			if err != nil {
				t.Fatalf("unknown error: %s", err)
			}

			got := IsGzip(bufio.NewReader(f))
			if got != tt.want {
				t.Errorf("got %t, want %t", got, tt.want)
			}
		})
	}
}

func TestIsExecutable(t *testing.T) {
	tests := []struct {
		name string
		mode fs.FileMode
		want bool
	}{
		{name: "bin/ls", mode: 0o755, want: true},
		{name: "etc/hosts", mode: 0o644, want: false},
		{name: "app/tool.exe", mode: 0o644, want: true},
		{name: "bin", mode: fs.ModeDir | 0o755, want: false},
		// Opening a named pipe blocks until a writer opens it.
		{name: "tmp/fifo.exe", mode: fs.ModeNamedPipe | 0o644, want: false},
		{name: "tmp/fifo", mode: fs.ModeNamedPipe | 0o755, want: false},
	}
	for _, tt := range tests {
		fsys := fstest.MapFS{tt.name: {Mode: tt.mode}}
		info, err := fsys.Stat(tt.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := IsExecutable(info); got != tt.want {
			t.Errorf("IsExecutable(%s, %v) = %v, want %v", tt.name, tt.mode, got, tt.want)
		}
	}
}

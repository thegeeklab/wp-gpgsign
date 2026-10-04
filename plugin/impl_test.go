package plugin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandGlobList(t *testing.T) {
	dir := t.TempDir()

	fileA := filepath.Join(dir, "a.txt")
	fileB := filepath.Join(dir, "b.txt")

	require.NoError(t, os.WriteFile(fileA, []byte("a"), 0o600))
	require.NoError(t, os.WriteFile(fileB, []byte("b"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "subdir"), 0o755))

	tests := []struct {
		name  string
		globs []string
		want  []string
	}{
		{
			name:  "single glob matches regular files",
			globs: []string{filepath.Join(dir, "*.txt")},
			want:  []string{fileA, fileB},
		},
		{
			name:  "glob matching directories filters them out",
			globs: []string{filepath.Join(dir, "*")},
			want:  []string{fileA, fileB},
		},
		{
			name:  "unmatched glob returns empty result",
			globs: []string{filepath.Join(dir, "*.nope")},
			want:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expandGlobList(tt.globs)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

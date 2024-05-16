package gnupg

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	switch os.Getenv("GO_TEST_MODE") {
	case "":
		// Normal test mode
		os.Exit(m.Run())

	case "pass":

	case "gpgconf --list-dirs":
		fmt.Println(`sysconfdir:/etc/gnupg
libexecdir:/usr/libexec
libdir:/usr/lib/gnupg
datadir:/usr/share/gnupg
homedir:/home/user/.gnupg`)

	case "gpg --version":
		fmt.Println(`gpg (GnuPG) 2.4.4
libgcrypt 1.10.2
Copyright (C) 2024 g10 Code GmbH`)

	default:
		fmt.Println("Unknown GO_TEST_MODE")
		os.Exit(1)
	}
}

func TestClient_SetHomedir(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		path    string
		want    *Client
		wantErr bool
	}{
		{
			name: "existing path",
			path: tmpDir,
			want: &Client{
				Env:     []string{fmt.Sprintf("GNUPGHOME=%s", tmpDir)},
				Homedir: tmpDir,
			},
		},
		{
			name: "valid path",
			path: filepath.Join(tmpDir, "subdir"),
			want: &Client{
				Env:     []string{fmt.Sprintf("GNUPGHOME=%s", filepath.Join(tmpDir, "subdir"))},
				Homedir: filepath.Join(tmpDir, "subdir"),
			},
		},
		{
			name:    "invalid path",
			path:    "/invalid/path",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{}

			err := c.SetHomedir(tt.path)
			if tt.wantErr {
				assert.Error(t, err)

				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, c)
		})
	}
}

func TestClient_GetDirs(t *testing.T) {
	tests := []struct {
		name    string
		env     []string
		want    Dirs
		wantErr bool
	}{
		{
			name: "success",
			env:  []string{"GO_TEST_MODE=gpgconf --list-dirs"},
			want: Dirs{
				Lib:     "/usr/lib/gnupg",
				Libexec: "/usr/libexec",
				Data:    "/usr/share/gnupg",
				Home:    "/home/user/.gnupg",
			},
			wantErr: false,
		},
		{
			name:    "fail",
			env:     []string{"GO_TEST_MODE=fail"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				gpgconfBin: os.Args[0],
				Env:        tt.env,
			}

			err := c.GetDirs()
			if tt.wantErr {
				assert.Error(t, err)

				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, c.Dirs)
		})
	}
}

func TestClient_GetVersion(t *testing.T) {
	tests := []struct {
		name    string
		bin     string
		env     []string
		want    *Version
		wantErr error
	}{
		{
			name: "success",
			bin:  os.Args[0],
			env:  []string{"GO_TEST_MODE=gpg --version"},
			want: &Version{
				Gnupg:     "2.4.4",
				Libgcrypt: "1.10.2",
			},
		},
		{
			name:    "fail",
			bin:     os.Args[0],
			env:     []string{"GO_TEST_MODE=fail"},
			wantErr: os.ErrExist,
		},
		{
			name:    "gpg binary not found",
			bin:     "invalid",
			wantErr: errBinaryNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				gpgBin: tt.bin,
				Env:    tt.env,
			}

			got, err := c.GetVersion()
			if tt.wantErr != nil {
				assert.Error(t, err)

				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

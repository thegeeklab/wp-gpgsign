package gnupg

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClient_SignFile(t *testing.T) {
	testFile := "/path/to/file"

	tests := []struct {
		name    string
		armor   bool
		detach  bool
		clear   bool
		path    string
		bin     string
		env     []string
		want    string
		wantErr error
	}{
		{
			name:   "sign file",
			armor:  false,
			detach: false,
			clear:  false,
			path:   testFile,
			bin:    os.Args[0],
			env:    []string{"GO_TEST_MODE=pass"},
			want: fmt.Sprintf(
				"gnupg.test -u %s! --batch --no-tty --yes --pinentry-mode loopback --passphrase-fd 0 --sign %s",
				testKeyFingerprint,
				testFile,
			),
		},
		{
			name:   "sign file with armor",
			armor:  true,
			detach: false,
			clear:  false,
			path:   testFile,
			bin:    os.Args[0],
			env:    []string{"GO_TEST_MODE=pass"},
			want: fmt.Sprintf(
				"gnupg.test -u %s! --batch --no-tty --yes --armor --pinentry-mode loopback --passphrase-fd 0 --sign %s",
				testKeyFingerprint,
				testFile,
			),
		},
		{
			name:   "detach sign file",
			armor:  false,
			detach: true,
			clear:  false,
			path:   testFile,
			bin:    os.Args[0],
			env:    []string{"GO_TEST_MODE=pass"},
			want: fmt.Sprintf(
				"gnupg.test -u %s! --batch --no-tty --yes --pinentry-mode loopback --passphrase-fd 0 --detach-sign %s",
				testKeyFingerprint,
				testFile,
			),
		},
		{
			name:   "clear sign file",
			armor:  false,
			detach: false,
			clear:  true,
			path:   testFile,
			bin:    os.Args[0],
			env:    []string{"GO_TEST_MODE=pass"},
			want: fmt.Sprintf(
				"gnupg.test -u %s! --batch --no-tty --yes --pinentry-mode loopback --passphrase-fd 0 --clear-sign %s",
				testKeyFingerprint,
				testFile,
			),
		},
		{
			name:    "gpg binary not found",
			bin:     "invalid",
			wantErr: errBinaryNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			c := &Client{
				gpgBin:      tt.bin,
				traceWriter: buf,
				Env:         tt.env,
				Key: Key{
					Fingerprint: testKeyFingerprint,
					Passphrase:  testPassphrase,
				},
			}

			err := c.SignFile(tt.armor, tt.detach, tt.clear, tt.path)

			assert.Contains(t, buf.String(), tt.want)

			if tt.wantErr != nil {
				assert.Error(t, err)

				return
			}

			assert.NoError(t, err)
		})
	}
}

package gnupg

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

//nolint:gosec,lll
const (
	testPrivateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
tA==
=fC40
-----END PGP PRIVATE KEY BLOCK-----`
	testPublicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBGXvbasBCACtmbDOqQGXxZvgzc3W3N71ccNoYlEhcF89HCIRubIpJ6TcPBvf
I3c4IKcwVQOyWWUz0+o3DITLAlTIuyCOyAudBSZf4tC7u1t4ViBfNaKN3Cm7Ktg4
o+BQ2BtAOla/2FIV835l0kKANwuWdu4LWi+5V4Wa/yAUWL8Ho0zRJXdyOdz7V4NS
uJ6oUJmPcuOIzNEvXfOhQN34chTrU80x8sqZmJviEIejvpZBbH+kZ1xIKZe4FULk
t2HraD0qMPH4aE2i40qSH/TAzn7cGdyCogdoqGyG24nv6jqDnWoEkmI9YE1NIDxq
NmVU+rBLxCSn8WOK0obTinft8PLSSZGTSu6vABEBAAG0MEpvaG4gRG9lIChEdW1t
eSB0ZXN0IGtleSkgPGpvaG4uZG9lQGV4YW1wbGUuY29tPokBUQQTAQgAOxYhBKsu
ohWKG2UMze17rwiOjBLYMbMbBQJl722rAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMB
Ah4HAheAAAoJEAiOjBLYMbMb+t4IAJq6HdlRBi5akNMcLIpjnjy+2J6Bwu+FWlSb
34xwv4FN2ZPDeC36P9XDwnipZUMrim+hP8IeMSwuWpuV86pBBVRiv2UqYWhkuJFE
0EdJpXE62kjxmMarKt7XmXBPDmanKFfecV1T3+oorouTgTstrZw6wvwQrpuA0l6l
TzbVqccqHrurkFTVTLweMMV+anDBzq3O1jrQW48k6nP8FmtJI3mDdtPssnxVM9iZ
zLSVW+YLTFIoFDBpNczsoM4zsfk900drhAjNwGh0XOO+9oSHkAYrynuBtoJC+1+h
AtkaCSvAM0d6jpIqWM7Amp6LDEIbAo55WUclh3PBawwpbL4w1Ui5AQ0EZe9tqwEI
AKZX8x8Xene6hkTSnzU94pf73J/biRXNXHniE0sSUhrDcxzndawQxQFEZKElaals
ChNaKbr4gLrmBGSUnRFGDjrbyOSpa/L5q0ECMXFcU1x3tHESFZwZ7efjdQ2V2v75
HXgMZ3AR/NkgB17jspx7lusWh+JnlykBA1IWBJRCPbzkfp5HNZWkiklSmieAJj0O
xppWSgs6WiFxTF3I2e6yiawQhPadoql5lXvh9DdKyqqwJgFHqdmqwH1FzvxgPsga
x3Znm4vdV8Vx2L6ouzfG/n4d31//HQB/DHsHYLVftBHWvmLBkSu0WJVDDmLOU8Vx
zDTNtuchEzui4LzfBp505S8AEQEAAYkBNgQYAQgAIBYhBKsuohWKG2UMze17rwiO
jBLYMbMbBQJl722rAhsMAAoJEAiOjBLYMbMbwn0H/2bWNbq6VlZ6+8h97jcYTSF5
WOIMcWo+7ZqBxBHo42jKgMQn1P5JvpewTMc/tS89n2ateO/ZNH2R57bblj87XXI0
8V+GgihWWMzH5Gec03mqoDj2qzFW3KCBmOf+n0mBfcGA89OjI42fpkOjBNNkqB7r
xAbDED+LOjteBkzbFsljKPphIFFnSie+o48t5en5V+xToeq9rS3aHl6fSKDWQh2B
DR26/jLw/MxN1+GAltDUUotwedOgyrnokXPFQrrGBgEfhpCSBpJxucMbSQuC8yZR
4895PbgzxWmcAjbEokCX9egdObVpGIqUkPIP3zGDpmcpWksTnMltE/mU5s8CZ7Q=
=qZCF
-----END PGP PUBLIC KEY BLOCK-----`
	testPrivatekeyBase64 = "LS0tLS1CRUdJTiBQR1AgUFJJVkFURSBLRVkgQkxPQ0stLS0tLQoKbFFQR0JHWHZiYXNCQ0FDdG1iRE9xUUdYeFp2Z3pjM1czTjcxY2NOb1lsRWhjRjg5SENJUnViSXBKNlRjUEJ2ZgpJM2M0SUtjd1ZRT3lXV1V6MCtvM0RJVExBbFRJdXlDT3lBdWRCU1pmNHRDN3UxdDRWaUJmTmFLTjNDbTdLdGc0Cm8rQlEyQnRBT2xhLzJGSVY4MzVsMGtLQU53dVdkdTRMV2krNVY0V2EveUFVV0w4SG8welJKWGR5T2R6N1Y0TlMKdUo2b1VKbVBjdU9Jek5FdlhmT2hRTjM0Y2hUclU4MHg4c3FabUp2aUVJZWp2cFpCYkgra1oxeElLWmU0RlVMawp0MkhyYUQwcU1QSDRhRTJpNDBxU0gvVEF6bjdjR2R5Q29nZG9xR3lHMjRudjZqcURuV29Fa21JOVlFMU5JRHhxCk5tVlUrckJMeENTbjhXT0swb2JUaW5mdDhQTFNTWkdUU3U2dkFCRUJBQUgrQndNQ2Z3a0xlNG9TeUNUL3hOM2YKenV4NG5jczB0WjRnZzdQZGxyMzg2ZHZSSzM1RStGQzBkb1lES29oallPTXF0Slh6ZllDQXNOekNmWDFOdUcydQowQlhCNFRVb3RoSEhDVGlqQ093UmxNUld3TUhTS3FldjRYOG9YU3hhSFBEbjdZRC9QNFlIM3RnK0tubHRId3BBCnFJSER4TVE1cStqZVRacFJNRUNmYzBMd1BnRUFzTVhsekVkOFZwY1ZBWERJN1VvZHplUWxjV0QzczZWZXlTdmwKM3VaNHdiZVlGM3c5VDJseEFhekNlMTRybWhXdmFlclY0Y3Q3YXkrTUQ2VUcyZFQwUmUxWGsveVI2MXpQS0xCbgozb3JPQUplZ1lNS0FNMlNBS0FlL3laWldwa29UUmJSOWRUQkNuSzQyWFZsSFhGWFQ0ZWNlaFFFNXNaL3M2MmNQCkcyZmVhbmxlUjF4YnJRQzIzYWRsWjdrVWs4enhqWGRFQ1RDQjVEcDYxSnVpMGVMbUovL2h0aE1tM1lnWktrZ08KSktwc05lRmhZdmh4M3Qzc0V1U24vWE40cmlHV2s0VWNsQnpLRUVYRmRDZlpDN0VlWFhJb2Z2dkFIaU9hZ1ZsaQpFekY2MTRvK0prb1J4M2UydU5pQUROR3k3alVCcHRuS2JCWjJkc2UyQ2E0a0lOcklyTFhzQUJrVU5NS2IrVHRVCnZBR0pNemN3OENiTjlVMkwvMVBKRGh2M3VTUnVReU5relYweVN6M0tQVlFOY2NPclgzTFRQcHBLL1VVdVY3ZmQKWWNrZUtHeXhZVjc0T2FnN3ZKYlNMK0FaekJBNjVlM2JBZmxyNlg5ZFlSblcxVnRBcEI0Y3k1K0VtNHgzMzJHTwpKdTdpRDkvUWF3bkt1RE5QcHJWZGRLK0M3S0NsSytQYnA5SVFwZTNOZVZuckN6QUNwTGYzakZ4UGNLQUJlZTZlCnJWWjNuUU5rSUxTd1IvcDgvWmZ0b1U5dkJ0WFk5Y0NDMjlTZ1JaN09PaTF3aUNtQnkycFVPWGFrVmNQQ0owWUUKQkJCOTB4ZVNOYWcvakJNM2xqVDgzdTNwWWRlM2xZV0cwb1NMS2YxVEpnaWtyaEJ0c3VHeVJLTTJvaUVHSTQ3TgpjYzdyZE1RK1l4UHcrUTVHUnJsU3JWNGNHOVBuREpMY1d5eEcwU2NPUlJmOFdCZ29Wa3F0TWZEMjdhUjJsNTRJCmN2dFVEUmV4RG9OYXREQktiMmh1SUVSdlpTQW9SSFZ0YlhrZ2RHVnpkQ0JyWlhrcElEeHFiMmh1TG1SdlpVQmwKZUdGdGNHeGxMbU52YlQ2SkFWRUVFd0VJQURzV0lRU3JMcUlWaWh0bERNM3RlNjhJam93UzJER3pHd1VDWmU5dApxd0liQXdVTENRZ0hBZ0lpQWdZVkNna0lDd0lFRmdJREFRSWVCd0lYZ0FBS0NSQUlqb3dTMkRHekcvcmVDQUNhCnVoM1pVUVl1V3BEVEhDeUtZNTQ4dnRpZWdjTHZoVnBVbTkrTWNMK0JUZG1UdzNndCtqL1Z3OEo0cVdWREs0cHYKb1QvQ0hqRXNMbHFibGZPcVFRVlVZcjlsS21Gb1pMaVJSTkJIU2FWeE90cEk4WmpHcXlyZTE1bHdUdzVtcHloWAozbkZkVTkvcUtLNkxrNEU3TGEyY09zTDhFSzZiZ05KZXBVODIxYW5IS2g2N3E1QlUxVXk4SGpERmZtcHd3YzZ0Cnp0WTYwRnVQSk9wei9CWnJTU041ZzNiVDdMSjhWVFBZbWN5MGxWdm1DMHhTS0JRd2FUWE03S0RPTTdINVBkTkgKYTRRSXpjQm9kRnpqdnZhRWg1QUdLOHA3Z2JhQ1F2dGZvUUxaR2drcndETkhlbzZTS2xqT3dKcWVpd3hDR3dLTwplVmxISllkendXc01LV3krTU5WSW5RUEdCR1h2YmFzQkNBQ21WL01mRjNwM3VvWkUwcDgxUGVLWCs5eWYyNGtWCnpWeDU0aE5MRWxJYXczTWM1M1dzRU1VQlJHU2hKV21wYkFvVFdpbTYrSUM2NWdSa2xKMFJSZzQ2Mjhqa3FXdnkKK2F0QkFqRnhYRk5jZDdSeEVoV2NHZTNuNDNVTmxkcisrUjE0REdkd0VmelpJQWRlNDdLY2U1YnJGb2ZpWjVjcApBUU5TRmdTVVFqMjg1SDZlUnpXVnBJcEpVcG9uZ0NZOURzYWFWa29MT2xvaGNVeGR5Tm51c29tc0VJVDJuYUtwCmVaVjc0ZlEzU3NxcXNDWUJSNm5acXNCOVJjNzhZRDdJR3NkMlo1dUwzVmZGY2RpK3FMczN4djUrSGQ5Zi94MEEKZnd4N0IyQzFYN1FSMXI1aXdaRXJ0RmlWUXc1aXpsUEZjY3cwemJibklSTTdvdUM4M3dhZWRPVXZBQkVCQUFIKwpCd01DUzRheVpJOWJWVkgvb09oNGpTR2lQM2o1clFDSDhSYnRtM2h0MzhSOVNtdlFQMW1wOUEvVHZLSi9VUm52Cmt2ZVNSWFhoL0FxTFVxTllHUURIdkJod0JrWnBNdTVCWUtrTUdSbFFsNmRLQ1MzNFR3TUp6emZYTEplZlE0czEKenpya2U1eGtIVGdQTmZjcmFjc1BjL2cwUmVpT1RrNWhaVktPNjBDRysvSlFQUEVOaGhCb1BFTHVVSWwzdGlTSQp5dzNWUmJFZjR5SUhxd2pETHJjU1kwYnpxMFEwa1lBSlUwOUtwa2oyTlFpOTBZYUhLUHl0cmswMnV0YzlKSGtyCkdTb3VaMjJnMUlPZ3dKOEtiL0FzbStjTkZBZ0MzNnBMeW40anJUamluNXU4SFJuRFk0WW01ek5Vcm5LSitWcWQKcXRFSHB6b3l3NjBTZWFtWTM5MEl2bk9GRmljT05aQkpUR0dYS3FuOXRVZ09CdnU1WC8wNFNaVzkzNDJieWRtNwpFdXp3UzkybFpzTmJQbUJuRDVHZUpNTUovRngvTncyWUd5dzBrUStzNVp6R2NYOEdjcEVINE1CTUt4TmZMV1RsCnN4by96T2orY1g1ZmxiZEk1S2xRa0s4NmRRK0tKSVZBYm9SNzExUURNTGdOakNRV0VkOUFySS9Ja0xYQTZlQmkKSDlodVlYMlVaUmMrU1dqYXR2c3dkUE9rcVN3YnFRb0h3Q010MWZKdGVwSEJGamE3UmRzOHBMVzA1QWNYMElybQovNFdrWnkzY3FFSEorSEdEa1hxVW5BWjQzMitQaXJKUUYxTFN4S0V3QjA1YUcrV0tZd0dpeGM3MFI0b2tlcmZmCkhFeS95S2YzSFpoWWhwMThESUQ0MVZpcEoreDdXNWFZUHNzRWc3M1FvQ0JiUUVxS3NmaTF4TmIzajNnaHM3SWMKMHNoUUNlMzFKbnpMalgwMGZrVFhwVnFBWS9NYzlseS9iZk9PaXhiMlJtMW1tTWVleEZwemFPM0tvakxnUHNBTwppUFBvZkp5NklidnVpUXVxYktjdnVWKzAzU3RJQnZQbVpqbzhSWk1pRmdIQ1RNQW5ZZTBvYmZka05rNWwxOUQyCnhvNEZBdVczamJqc08vaVM3MDNNSC9WcEhzWXVQQmxrWERlSEt5cGVrOEV3cHJhNGQ4TjNIRy9HRzhvNVhOdnEKelI4OGxTbXVLSFV1UXhCOUg2L2g3emJ1SDRMRnhqRjRpUUUyQkJnQkNBQWdGaUVFcXk2aUZZb2JaUXpON1h1dgpDSTZNRXRneHN4c0ZBbVh2YmFzQ0d3d0FDZ2tRQ0k2TUV0Z3hzeHZDZlFmL1p0WTF1cnBXVm5yN3lIM3VOeGhOCklYbFk0Z3h4YWo3dG1vSEVFZWpqYU1xQXhDZlUva20rbDdCTXh6KzFMejJmWnExNDc5azBmWkhudHR1V1B6dGQKY2pUeFg0YUNLRlpZek1ma1o1elRlYXFnT1Bhck1WYmNvSUdZNS82ZlNZRjl3WUR6MDZNampaK21RNk1FMDJTbwpIdXZFQnNNUVA0czZPMTRHVE5zV3lXTW8rbUVnVVdkS0o3NmpqeTNsNmZsWDdGT2g2cjJ0TGRvZVhwOUlvTlpDCkhZRU5IYnIrTXZEOHpFM1g0WUNXME5SU2kzQjUwNkRLdWVpUmM4VkN1c1lHQVIrR2tKSUdrbkc1d3h0SkM0THoKSmxIanozazl1RFBGYVp3Q05zU2lRSmYxNkIwNXRXa1lpcFNROGcvZk1ZT21aeWxhU3hPY3lXMFQrWlRtendKbgp0QT09Cj1mQzQwCi0tLS0tRU5EIFBHUCBQUklWQVRFIEtFWSBCTE9DSy0tLS0tCg=="
	testPassphrase       = "dummypass"
	testKeyID            = "088E8C12D831B31B"
	testKeyFingerprint   = "AB2EA2158A1B650CCDED7BAF088E8C12D831B31B"
	testKeyIdentity      = "John Doe (Dummy test key) <john.doe@example.com>"
	testKeyCreation      = "2024-03-11 21:46:35 +0100 CET"
)

var errBinaryNotFound = errors.New("failed to find gpg binary")

func TestIsArmored(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{
			name:     "valid armored key",
			key:      testPrivateKey,
			expected: true,
		},
		{
			name:     "valid unarmored key",
			key:      testPrivatekeyBase64,
			expected: false,
		},
		{
			name:     "empty key",
			key:      "",
			expected: false,
		},
		{
			name:     "invalid key",
			key:      "invalid key",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsArmored(tt.key)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestReadPrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr error
	}{
		{
			name:    "success",
			key:     testPrivateKey,
			wantErr: nil,
		},
		{
			name:    "error parsing key",
			key:     "invalid",
			wantErr: ErrReadKeyFailed,
		},
	}

	for _, tt := range tests {
		gpgclient, _ := New(tt.key, "")

		t.Run(tt.name, func(t *testing.T) {
			err := gpgclient.ReadPrivateKey()
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)

				return
			}

			testKeyCreation, _ := time.Parse("2006-01-02 15:04:05 -0700 MST", testKeyCreation)

			assert.NoError(t, err)
			assert.Equal(t, gpgclient.Key.ID, testKeyID)
			assert.Equal(t, gpgclient.Key.Fingerprint, testKeyFingerprint)
			assert.Equal(t, gpgclient.Key.Identity, testKeyIdentity)
			assert.Equal(t, gpgclient.Key.CreationTime, testKeyCreation.UTC())
		})
	}
}

func TestClient_ImportKey(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		bin     string
		env     []string
		want    []string
		wantErr error
	}{
		{
			name: "success",
			key:  testPrivateKey,
			bin:  os.Args[0],
			env:  []string{"GO_TEST_MODE=pass"},
			want: []string{"gnupg.test --batch --import -"},
		},
		{
			name:    "gpg binary not found",
			bin:     "invalid",
			key:     testPrivateKey,
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
					Content: tt.key,
				},
			}

			err := c.ImportKey()

			for _, l := range tt.want {
				assert.Contains(t, buf.String(), l)
			}

			if tt.wantErr != nil {
				assert.Error(t, err)

				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestClient_SetTrustLevel(t *testing.T) {
	tests := []struct {
		name    string
		level   string
		bin     string
		env     []string
		want    []string
		wantErr error
	}{
		{
			name:  "valid trust level",
			level: "full",
			bin:   os.Args[0],
			env:   []string{"GO_TEST_MODE=pass"},
			want:  []string{fmt.Sprintf("gnupg.test --batch --no-tty --command-fd 0 --edit-key %s", testKeyID)},
		},
		{
			name:    "invalid trust level",
			level:   "invalid",
			bin:     os.Args[0],
			wantErr: ErrInvalidTrustLevel,
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
					ID: testKeyID,
				},
			}

			err := c.SetTrustLevel(tt.level)

			for _, l := range tt.want {
				assert.Contains(t, buf.String(), l)
			}

			if tt.wantErr != nil {
				assert.Error(t, err)

				return
			}

			assert.NoError(t, err)
		})
	}
}

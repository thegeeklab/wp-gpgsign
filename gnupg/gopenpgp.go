package gnupg

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

var (
	ErrPrimaryIdentityNotFound = errors.New("no primary identity found")
	ErrReadKeyFailed           = errors.New("failed to read private key")
)

// IsArmored checks if the given key is armored by trying to parse it.
// Returns true if the key is armored, false otherwise.
func IsArmored(key string) bool {
	_, err := crypto.NewKeyFromArmored(key)

	return err == nil
}

// ReadPrivateKey reads a private key from the given Key struct.
// It parses the armored key content into a gopenpgp private key.
// It returns the key ID, creation time, identity, and fingerprint.
// It returns an error if the key could not be parsed or the primary identity was not found.
func (c *Client) ReadPrivateKey() error {
	gkey, err := crypto.NewKeyFromArmored(c.Key.Content)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrReadKeyFailed, err)
	}

	entity := gkey.GetEntity()
	primary := entity.PrimaryKey

	c.Key.ID = primary.KeyIdString()
	c.Key.CreationTime = primary.CreationTime.UTC()
	c.Key.Identity = entity.PrimaryIdentity().Name
	c.Key.Fingerprint = strings.ToUpper(hex.EncodeToString(primary.Fingerprint))

	if c.Key.Identity == "" {
		return ErrPrimaryIdentityNotFound
	}

	return nil
}

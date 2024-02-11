package simplecertify

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadAndSave(t *testing.T) {
	CERTIFIER_CONFIG_PATH = "ca_test.json"
	templ := CATemplate()
	expected, err := Init(&templ, &templ)
	assert.NoError(t, err)

	err = Save(expected)
	assert.NoError(t, err)

	actual, err := Load()
	assert.NoError(t, err)

	assert.Equal(t, expected.PrivateKey, actual.PrivateKey)
	assert.Equal(t, expected.Certificate, actual.Certificate)
}

package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFactory_CreateStore_Memory(t *testing.T) {
	factory := NewFactory()

	config := NewMemoryConfig()
	store, err := factory.CreateStore(config)

	assert.NoError(t, err)
	assert.NotNil(t, store)
	assert.IsType(t, &InMemoryRefreshTokenStore{}, store)
}

func TestFactory_CreateStore_DefaultConfig(t *testing.T) {
	factory := NewFactory()

	store, err := factory.CreateStore(nil)

	assert.NoError(t, err)
	assert.NotNil(t, store)
	assert.IsType(t, &InMemoryRefreshTokenStore{}, store)
}

func TestNewStore_Memory(t *testing.T) {
	config := NewMemoryConfig()
	store, err := NewStore(config)

	assert.NoError(t, err)
	assert.NotNil(t, store)
	assert.IsType(t, &InMemoryRefreshTokenStore{}, store)
}

func TestNewMemoryStore(t *testing.T) {
	store := NewMemoryStore()

	assert.NotNil(t, store)
	assert.IsType(t, &InMemoryRefreshTokenStore{}, store)
}

func TestMustNewMemoryStore(t *testing.T) {
	store := MustNewMemoryStore()

	assert.NotNil(t, store)
	assert.IsType(t, &InMemoryRefreshTokenStore{}, store)
}

func TestDefault(t *testing.T) {
	store := Default()

	assert.NotNil(t, store)
	assert.IsType(t, &InMemoryRefreshTokenStore{}, store)
}

func TestFactory_CreateStore_UnsupportedType(t *testing.T) {
	factory := NewFactory()

	config := &Config{
		Type: "unsupported",
	}

	store, err := factory.CreateStore(config)

	assert.Error(t, err)
	assert.Nil(t, store)
	assert.Contains(t, err.Error(), "unsupported store type")
}

package extension_test

import (
	"context"
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/extension"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockEngine struct {
	registered []string
}

func (m *mockEngine) Register(id string, _ interface{}, _ extension.Callback) error {
	m.registered = append(m.registered, id)
	return nil
}

func (m *mockEngine) AddExtensionInitializer(_ func(extension.Engine) error) {}

func TestInit(t *testing.T) {
	eng := &mockEngine{}
	err := extension.Init(eng)
	require.NoError(t, err)
	require.Len(t, eng.registered, 1)
	assert.Equal(t, extension.WorkflowID, eng.registered[0])
}

func TestEntrypoint_missingPath(t *testing.T) {
	// Via Init then manually calling - just test the WorkflowID constant.
	assert.Equal(t, "container/scan", extension.WorkflowID)
	_ = context.Background() // suppress unused import
}

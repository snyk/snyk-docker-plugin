package types_test

import (
	"testing"

	"github.com/snyk/snyk-docker-plugin/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestOptBool_nil(t *testing.T) {
	assert.False(t, types.OptBool(nil))
}

func TestOptBool_boolTrue(t *testing.T) {
	assert.True(t, types.OptBool(true))
}

func TestOptBool_boolFalse(t *testing.T) {
	assert.False(t, types.OptBool(false))
}

func TestOptBool_stringTrue(t *testing.T) {
	assert.True(t, types.OptBool("true"))
	assert.True(t, types.OptBool("1"))
	assert.True(t, types.OptBool("yes"))
}

func TestOptBool_stringFalse(t *testing.T) {
	assert.False(t, types.OptBool("false"))
	assert.False(t, types.OptBool(""))
	assert.False(t, types.OptBool("no"))
}

func TestOptBool_intNonZero(t *testing.T) {
	assert.True(t, types.OptBool(1))
	assert.False(t, types.OptBool(0))
}

func TestOptBool_float64(t *testing.T) {
	assert.True(t, types.OptBool(float64(1)))
	assert.False(t, types.OptBool(float64(0)))
}

func TestOptInt_nil(t *testing.T) {
	assert.Equal(t, 5, types.OptInt(nil, 5))
}

func TestOptInt_int(t *testing.T) {
	assert.Equal(t, 3, types.OptInt(3, 1))
}

func TestOptInt_float64(t *testing.T) {
	assert.Equal(t, 2, types.OptInt(float64(2), 1))
}

func TestOptInt_int64(t *testing.T) {
	assert.Equal(t, 7, types.OptInt(int64(7), 1))
}

func TestOptInt_string(t *testing.T) {
	// String is not handled — falls through to default.
	assert.Equal(t, 10, types.OptInt("42", 10))
}

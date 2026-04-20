package errors

import (
	"errors"
	"fmt"
	"testing"
)

func TestCodeOf_WrappedError(t *testing.T) {
	t.Parallel()
	inner := New(CodeInvalidField, "inner")
	wrapped := fmt.Errorf("wrap: %w", inner)
	if got := CodeOf(wrapped); got != string(CodeInvalidField) {
		t.Fatalf("CodeOf = %q, want %q", got, CodeInvalidField)
	}
}

func TestCodeOf_NonSecurityError(t *testing.T) {
	t.Parallel()
	if got := CodeOf(errors.New("plain")); got != "" {
		t.Fatalf("CodeOf = %q, want empty", got)
	}
}

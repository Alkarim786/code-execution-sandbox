package service

import (
	"testing"

	"github.com/Alkarim786/code-execution-sandbox/internal/languages"
)

func mustLang(t *testing.T, name string) *languages.Language {
	t.Helper()
	l, err := languages.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

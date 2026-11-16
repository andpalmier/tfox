package cmd

import (
	"os"
	"strings"
	"testing"
)

func TestExecuteLeavesSubcommandFlagValueAlone(t *testing.T) {
	t.Setenv("ABUSECH_API_KEY", "")
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"tfox", "submit", "-threat_type", "botnet_cc", "-ioc_type", "domain", "-malware", "Emotet", "-ioc", "evil.example", "-comment", "-t"}

	err := Execute()
	if err == nil || !strings.Contains(err.Error(), "ABUSECH_API_KEY environment variable is required") {
		t.Fatalf("Execute() error = %v, want missing API key", err)
	}
}

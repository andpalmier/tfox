package cmd

import "testing"

func TestCommandValidationRejectsBeforeNetwork(t *testing.T) {
	tests := []struct {
		name string
		fn   func([]string) error
		args []string
	}{
		{"recent invalid days", executeRecent, []string{"-days", "0"}},
		{"query no selector", executeQuery, []string{"-limit", "10"}},
		{"query multiple selectors", executeQuery, []string{"-tag", "Emotet", "-malware", "Emotet"}},
		{"search no selector", executeSearch, []string{"-exact"}},
		{"search multiple selectors", executeSearch, []string{"-ioc", "evil.example", "-hash", "d41d8cd98f00b204e9800998ecf8427e"}},
		{"list no type", executeList, []string{}},
		{"list multiple types", executeList, []string{"-malware", "-types"}},
		{"submit missing fields", executeSubmit, nil},
		{"submit bad confidence", executeSubmit, []string{"-threat_type", "botnet_cc", "-ioc_type", "domain", "-malware", "Emotet", "-ioc", "evil.example", "-confidence", "101"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(tt.args); err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestRepeatableFlag(t *testing.T) {
	var r repeatableFlag
	if err := r.Set(""); err == nil {
		t.Error("empty value accepted")
	}
	if err := r.Set("evil.example"); err != nil {
		t.Fatal(err)
	}
	if got := r.String(); got != "evil.example" {
		t.Errorf("String() = %q", got)
	}
}

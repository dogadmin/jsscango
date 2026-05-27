package rules

import (
	"testing"
)

func TestLoadDefault(t *testing.T) {
	s, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(s.Rules) == 0 {
		t.Fatal("no rules loaded")
	}
	if len(s.BlackText) == 0 {
		t.Fatal("no black text markers")
	}
	if errs := s.CompileErrors(); len(errs) > 0 {
		for id, err := range errs {
			t.Errorf("rule %q failed to compile: %v", id, err)
		}
	}
}

func TestApplyFindsJWT(t *testing.T) {
	s, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsIm5hbWUiOiJBbGljZSJ9.5lABDsT0Q3JaQwBJ1lYU0L8aRl5GckkBdLb0sH9_pjE`)
	hits := s.Apply(body)
	gotJWT := false
	for _, h := range hits {
		if h.RuleID == "jwt_token" {
			gotJWT = true
			if len(h.Matches) == 0 {
				t.Error("jwt_token matched but Matches is empty")
			}
		}
	}
	if !gotJWT {
		t.Errorf("expected jwt_token match, got rules: %v", ruleIDs(hits))
	}
}

func TestIsBlackText(t *testing.T) {
	s, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !s.IsBlackText([]byte(`some response containing "未找到API注册信息" mid-string`)) {
		t.Error("expected BLACK_TEXT match for 未找到API注册信息")
	}
	if s.IsBlackText([]byte(`a perfectly fine response`)) {
		t.Error("false positive on benign response")
	}
}

func ruleIDs(hits []Hit) []string {
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.RuleID)
	}
	return out
}

func TestEmbeddedFiles(t *testing.T) {
	files := EmbeddedFiles()
	for _, name := range []string{"rules.yaml", "blacktext.yaml"} {
		b, ok := files[name]
		if !ok {
			t.Errorf("EmbeddedFiles missing key %q", name)
			continue
		}
		if len(b) == 0 {
			t.Errorf("EmbeddedFiles[%q] is empty", name)
		}
	}
	if len(EmbeddedRulesYAML()) == 0 {
		t.Error("EmbeddedRulesYAML returned empty bytes")
	}
	if len(EmbeddedBlackTextYAML()) == 0 {
		t.Error("EmbeddedBlackTextYAML returned empty bytes")
	}
}

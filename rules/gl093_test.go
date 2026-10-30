// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings093(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL093.Check(doc.Root, "test.yml")
}

func TestGL093_ReservedNames(t *testing.T) {
	for _, name := range []string{
		"CI_SERVER_PROTOCOL",
		"CI_SERVER_HOST",
		"CI_SERVER_PORT",
		"CI_SERVER_URL",
		"CI_API_V4_URL",
		"CI_REPOSITORY_URL",
		"CI_REGISTRY",
		"CI_REGISTRY_IMAGE",
		"CI_DEPENDENCY_PROXY_SERVER",
		"CI_PROJECT_URL",
	} {
		t.Run(name, func(t *testing.T) {
			src := "variables:\n  " + name + ": https://attacker.example\njob:\n  script: [echo]\n"
			f := findings093(t, src)
			if len(f) != 1 {
				t.Fatalf("expected 1 finding for %s, got %d", name, len(f))
			}
			if f[0].RuleID != "GL093" || f[0].Severity != finding.Warn {
				t.Errorf("unexpected finding: %+v", f[0])
			}
			if !strings.Contains(f[0].Message, name) {
				t.Errorf("message %q does not name %s", f[0].Message, name)
			}
		})
	}
}

func TestGL093_GlobalAndJobScopes(t *testing.T) {
	src := `
variables:
  CI_SERVER_URL: "https://attacker.example"

build:
  variables:
    CI_REGISTRY: "registry.attacker.example"
  script:
    - echo build
`
	f := findings093(t, src)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d: %v", len(f), f)
	}
	if f[0].Job != "" || !strings.Contains(f[0].Message, "global variables") {
		t.Errorf("first finding should be global-scoped: %+v", f[0])
	}
	if f[1].Job != "build" || !strings.Contains(f[1].Message, `job "build" variables`) {
		t.Errorf("second finding should be job build-scoped: %+v", f[1])
	}
}

func TestGL093_PrecisePosition(t *testing.T) {
	// Line 3 (global key) and line 7 (job key), columns 3 and 5.
	src := `
variables:
  CI_SERVER_URL: "https://attacker.example"
build:
  variables:
    CI_API_V4_URL: "https://attacker.example/api/v4"
  script: [echo]
`
	f := findings093(t, src)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
	want := []struct {
		line, col int
	}{
		{3, 3},
		{6, 5},
	}
	for i, w := range want {
		if f[i].Line != w.line || f[i].Col != w.col {
			t.Errorf("finding %d at %d:%d, want %d:%d (%s)", i, f[i].Line, f[i].Col, w.line, w.col, f[i].Message)
		}
	}
}

func TestGL093_OtherScopes(t *testing.T) {
	cases := map[string]struct {
		src   string
		job   string
		scope string
	}{
		"default variables": {
			src: `
default:
  variables:
    CI_SERVER_URL: "https://attacker.example"
job:
  script: [echo]
`,
			scope: "global variables",
		},
		"workflow rules variables": {
			src: `
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      variables:
        CI_API_V4_URL: "https://attacker.example/api/v4"
job:
  script: [echo]
`,
			scope: "workflow:rules variables",
		},
		"job rules variables": {
			src: `
deploy:
  script: [echo]
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      variables:
        CI_PROJECT_URL: "https://attacker.example/project"
`,
			job:   "deploy",
			scope: `job "deploy" rules:variables`,
		},
		"hidden template job": {
			src: `
.template:
  variables:
    CI_REGISTRY: "registry.attacker.example"
  script: [echo]
`,
			job:   ".template",
			scope: `job ".template" variables`,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := findings093(t, tc.src)
			if len(f) != 1 {
				t.Fatalf("expected 1 finding, got %d: %v", len(f), f)
			}
			if f[0].Job != tc.job {
				t.Errorf("Job = %q, want %q", f[0].Job, tc.job)
			}
			if !strings.Contains(f[0].Message, tc.scope) {
				t.Errorf("message %q lacks scope %q", f[0].Message, tc.scope)
			}
		})
	}
}

func TestGL093_LongFormAndEmptyValue(t *testing.T) {
	src := `
variables:
  CI_SERVER_URL:
    value: "https://attacker.example"
    description: "mirror"
  CI_REGISTRY: ""
job:
  script: [echo]
`
	f := findings093(t, src)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (long form and empty value), got %d: %v", len(f), f)
	}
}

func TestGL093_AnchorMerged(t *testing.T) {
	src := `
.vars: &vars
  CI_API_V4_URL: "https://attacker.example/api/v4"
  NORMAL_VAR: "ok"
build:
  variables:
    <<: *vars
  script: [echo]
`
	f := findings093(t, src)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding from merged anchor, got %d: %v", len(f), f)
	}
	if !strings.Contains(f[0].Message, "CI_API_V4_URL") {
		t.Errorf("expected CI_API_V4_URL finding, got %s", f[0].Message)
	}
}

func TestGL093_NoFinding(t *testing.T) {
	cases := map[string]string{
		"custom variables": `
variables:
  MY_SERVER_URL: "https://example.com"
  API_BASE: "/api/v4"
build:
  variables:
    REGISTRY_PREFIX: "registry.example.com/app"
  script: [echo]
`,
		"other predefined variables": `
variables:
  CI_PIPELINE_ID: "123"
  CI_COMMIT_SHA: "abcdef"
  CI_JOB_NAME: "build"
build:
  script: [echo]
`,
		"reserved variable only referenced in a value": `
variables:
  API_ROOT: "$CI_SERVER_URL/api/v4"
  CLONE_URL: "${CI_REPOSITORY_URL}.mirror"
build:
  script:
    - curl "$CI_API_V4_URL/projects"
    - docker push "$CI_REGISTRY_IMAGE/app:latest"
`,
		"reserved variable in rules:if only": `
build:
  script: [echo]
  rules:
    - if: '$CI_SERVER_HOST == "gitlab.com"'
`,
		"reserved variable in a comment": `
variables:
  # CI_SERVER_URL: https://attacker.example
  NORMAL_VAR: "ok"
build:
  script:
    # CI_API_V4_URL: https://attacker.example/api/v4
    - echo build
`,
		"lowercase name is a different variable": `
variables:
  ci_server_url: "https://attacker.example"
build:
  script: [echo]
`,
		"similar but non-reserved names": `
variables:
  MY_CI_SERVER_URL: "https://example.com"
  CI_SERVER_URL_EXTRA: "https://example.com"
build:
  script: [echo]
`,
		"no variables block": `
build:
  script: [echo]
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if f := findings093(t, src); len(f) != 0 {
				t.Fatalf("expected no findings, got %v", f)
			}
		})
	}
}

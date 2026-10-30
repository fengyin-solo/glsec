// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings091(t *testing.T, yamlSrc string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yamlSrc), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL091.Check(doc.Root, "test.yml")
}

func TestGL091_Flagged(t *testing.T) {
	cases := map[string]string{
		"deploy stage": `
stages: [test, deploy]

deploy_prod:
  stage: deploy
  needs:
    - job: sast
      optional: true
  script: [./deploy.sh]
`,
		"environment without stage": `
deploy_prod:
  environment: production
  needs:
    - job: sast
      optional: true
  script: [./deploy.sh]
`,
		"environment mapping form": `
deploy_prod:
  environment:
    name: production
  needs:
    - job: sast
      optional: true
  script: [./deploy.sh]
`,
		"quoted string true": `
deploy_prod:
  stage: deploy
  needs:
    - job: sast
      optional: "true"
  script: [./deploy.sh]
`,
		"stage inherited via extends": `
.deploy_base:
  stage: deploy
deploy_prod:
  extends: .deploy_base
  needs:
    - job: sast
      optional: true
  script: [./deploy.sh]
`,
		"environment inherited via extends": `
.deploy_base:
  environment: production
deploy_prod:
  extends: .deploy_base
  needs:
    - job: sast
      optional: true
  script: [./deploy.sh]
`,
		"multiple offending needs": `
deploy_prod:
  stage: deploy
  needs:
    - job: sast
      optional: true
    - job: secret_detection
      optional: true
  script: [./deploy.sh]
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			f := findings091(t, src)
			if len(f) == 0 {
				t.Fatalf("expected at least 1 finding, got 0")
			}
			if strings.Contains(name, "multiple") {
				if len(f) != 2 {
					t.Fatalf("expected 2 findings, got %d: %v", len(f), f)
				}
			} else if len(f) != 1 {
				t.Fatalf("expected 1 finding, got %d: %v", len(f), f)
			}
			for _, got := range f {
				if got.RuleID != "GL091" || got.Severity != finding.Warn {
					t.Errorf("unexpected finding: %+v", got)
				}
				if got.Job != "deploy_prod" {
					t.Errorf("expected Job=deploy_prod, got %q", got.Job)
				}
				if !strings.Contains(got.Message, "sast") && !strings.Contains(got.Message, "secret_detection") {
					t.Errorf("message should name the needed job, got %q", got.Message)
				}
				if got.Line == 0 || got.Col == 0 {
					t.Errorf("finding has no source location: %+v", got)
				}
			}
		})
	}
}

func TestGL091_LocationPointsAtOptional(t *testing.T) {
	src := `stages: [test, deploy]

deploy_prod:
  stage: deploy
  needs:
    - job: sast
      optional: true
  script: [./deploy.sh]
`
	f := findings091(t, src)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	lines := strings.Split(src, "\n")
	// f.Line is 1-based; the reported line must be the optional: true line.
	gotLine := lines[f[0].Line-1]
	if !strings.Contains(gotLine, "optional: true") {
		t.Errorf("expected location on the optional: true line, got line %d: %q", f[0].Line, gotLine)
	}
}

func TestGL091_NoFinding(t *testing.T) {
	cases := map[string]string{
		"string need": `
deploy_prod:
  stage: deploy
  needs:
    - sast
    - secret_detection
  script: [./deploy.sh]
`,
		"flow-style string need": `
deploy_prod:
  environment: production
  needs: [sast]
  script: [./deploy.sh]
`,
		"mapping without optional": `
deploy_prod:
  stage: deploy
  needs:
    - job: sast
  script: [./deploy.sh]
`,
		"optional false": `
deploy_prod:
  stage: deploy
  needs:
    - job: sast
      optional: false
  script: [./deploy.sh]
`,
		"mix of required and string needs": `
deploy_prod:
  stage: deploy
  needs:
    - sast
    - job: secret_detection
  script: [./deploy.sh]
`,
		"non-deploy job with optional need": `
build:
  stage: build
  needs:
    - job: maybe_missing
      optional: true
  script: [make build]
`,
		"deploy-named job outside deploy stage": `
deploy_helper:
  stage: test
  needs:
    - job: sast
      optional: true
  script: [./help.sh]
`,
		"non-deploy stage name": `
rollout_job:
  stage: deployment
  needs:
    - job: sast
      optional: true
  script: [./deploy.sh]
`,
		"hidden template job": `
.deploy_template:
  stage: deploy
  environment: production
  needs:
    - job: sast
      optional: true
  script: [./deploy.sh]
`,
		"no needs": `
deploy_prod:
  stage: deploy
  environment: production
  script: [./deploy.sh]
`,
		"needs not a sequence": `
deploy_prod:
  stage: deploy
  needs: sast
  script: [./deploy.sh]
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if f := findings091(t, src); len(f) != 0 {
				t.Fatalf("expected no finding, got %v", f)
			}
		})
	}
}

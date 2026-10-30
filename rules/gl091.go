// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl091 struct{}

var GL091 = &gl091{}

func (r *gl091) ID() string { return "GL091" }

// Check reports a deploy job whose needs: long-form entry sets optional: true.
// An optional need is not added to the pipeline when the needed job does not
// exist there (its rules:/only: did not create it), so a deploy that treats a
// security job as a gate still runs when the gate is absent. Only jobs that
// deploy — they declare an environment: or run in a stage named "deploy" —
// are checked; a string need and a mapping without optional: true stay silent.
func (r *gl091) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	in := NewInheritance(doc)

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if strings.HasPrefix(name.Value, ".") || !gl091Deploys(in, job) {
			return
		}
		needs := parser.FindKey(job, "needs")
		if needs == nil || needs.Kind != yaml.SequenceNode {
			return
		}
		for _, item := range needs.Content {
			if item.Kind != yaml.MappingNode {
				continue // string form ("- job_name") cannot carry optional:
			}
			optional := parser.FindKey(item, "optional")
			if optional == nil || optional.Kind != yaml.ScalarNode ||
				!strings.EqualFold(optional.Value, "true") {
				continue
			}
			findings = append(findings, gl091Finding(name.Value, item, optional, file))
		}
	})

	return findings
}

// gl091Deploys is the narrow deploy definition GL091 uses: the job declares
// an environment: (its own or inherited) or its stage is named "deploy"
// (GitLab's default deploy stage). The job name alone does not count.
func gl091Deploys(in *Inheritance, job *yaml.Node) bool {
	if in.Key(job, "environment") != nil {
		return true
	}
	stage := in.Key(job, "stage")
	return stage != nil && stage.Kind == yaml.ScalarNode &&
		strings.EqualFold(strings.TrimSpace(stage.Value), "deploy")
}

func gl091Finding(jobName string, item, optional *yaml.Node, file string) finding.Finding {
	message := fmt.Sprintf(
		"deploy job %q marks a needs entry as optional: true — the deploy runs even if that job is never created in the pipeline (its rules:/only: exclude it) or does not run, so a prerequisite security gate can silently drop out; remove optional: true for a required gate",
		jobName,
	)
	if dep := parser.FindKey(item, "job"); dep != nil && dep.Kind == yaml.ScalarNode && dep.Value != "" {
		message = fmt.Sprintf(
			"deploy job %q marks needed job %q as optional: true — the deploy runs even if %q is never created in the pipeline (its rules:/only: exclude it) or does not run, so a prerequisite security gate can silently drop out; remove optional: true for a required gate",
			jobName, dep.Value, dep.Value,
		)
	}
	return finding.Finding{
		RuleID:   "GL091",
		Severity: finding.Warn,
		Job:      jobName,
		Message:  message,
		File:     file,
		Line:     optional.Line,
		Col:      optional.Column,
	}
}

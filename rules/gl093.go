// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl093 struct{}

var GL093 = &gl093{}

func (r *gl093) ID() string { return "GL093" }

// reservedEndpointVars are the predefined CI/CD variables that pin the
// endpoints GitLab-provided clients connect to and that job or registry
// tokens are sent to: the instance URL and its protocol/host/port parts,
// the API root, the repository clone URL, the container registry and its
// image prefix, the Dependency Proxy server, and the project URL. GitLab
// injects these from the server configuration; defining one in the
// pipeline file overrides that value and moves the trust boundary to
// whoever chose the value in the file.
var reservedEndpointVars = map[string]bool{
	"CI_SERVER_PROTOCOL":         true,
	"CI_SERVER_HOST":             true,
	"CI_SERVER_PORT":             true,
	"CI_SERVER_URL":              true,
	"CI_API_V4_URL":              true,
	"CI_REPOSITORY_URL":          true,
	"CI_REGISTRY":                true,
	"CI_REGISTRY_IMAGE":          true,
	"CI_DEPENDENCY_PROXY_SERVER": true,
	"CI_PROJECT_URL":             true,
}

// Check reports every redefinition of a reserved endpoint variable in a
// variables: block GitLab can apply: top-level, default:, workflow:rules,
// per job, and job rules: entries. Each definition is one warn carrying
// the variable name, its scope and the key's position.
func (r *gl093) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	eachVariablesBlock(doc, func(vars *yaml.Node, job string, rule *yaml.Node) {
		if vars == nil || vars.Kind != yaml.MappingNode {
			return
		}
		scope := variableScope(job, rule)
		for i := 0; i+1 < len(vars.Content); i += 2 {
			nameNode := vars.Content[i]
			if nameNode.Kind != yaml.ScalarNode || !reservedEndpointVars[nameNode.Value] {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL093",
				Severity: finding.Warn,
				Job:      job,
				Message: fmt.Sprintf(
					"predefined CI/CD variable %q is redefined in %s — GitLab injects it to pin the host its clients connect to and where tokens (CI_JOB_TOKEN, registry credentials) are sent; overriding it here redirects those clients to a host chosen in this file and changes the trust boundary",
					nameNode.Value, scope,
				),
				File: file,
				Line: nameNode.Line,
				Col:  nameNode.Column,
			})
		}
	})
	return findings
}

// variableScope describes the variables: block a finding belongs to, the
// way GitLab documentation scopes it: global variables, default:, a
// workflow:rules entry, a job, or a job's rules: entry.
func variableScope(job string, rule *yaml.Node) string {
	switch {
	case job != "" && rule != nil:
		return fmt.Sprintf("job %q rules:variables", job)
	case job != "":
		return fmt.Sprintf("job %q variables", job)
	case rule != nil:
		return "workflow:rules variables"
	default:
		return "global variables"
	}
}

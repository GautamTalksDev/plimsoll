// Copyright 2026 The PLIMSOLL Authors
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package seal implements prereg-v1 pre-registration objects: parse,
// validate, canonical hash, and Ed25519 sign/verify. Evaluation of
// decision rules is not performed here. The package never holds
// datasets, models, prompts, or outputs — digests and metadata only.
package seal

const (
	Version      = "prereg-v1"
	CanonVersion = "plimsoll-canon-v1"
)

// Seal is a prereg-v1 pre-registration. It contains only metadata and
// digests. It never holds datasets, models, prompts, or outputs.
type Seal struct {
	PlimsollVersion string       `json:"plimsoll_version" yaml:"plimsoll_version"`
	CreatedAt       string       `json:"created_at" yaml:"created_at"`
	Subject         Subject      `json:"subject" yaml:"subject"`
	Dataset         Dataset      `json:"dataset" yaml:"dataset"`
	Harness         Harness      `json:"harness" yaml:"harness"`
	Metrics         []Metric     `json:"metrics" yaml:"metrics"`
	DecisionRule    DecisionRule `json:"decision_rule" yaml:"decision_rule"`
	Exclusions      []string     `json:"exclusions" yaml:"exclusions"`
	PlannedAttempts int          `json:"planned_attempts" yaml:"planned_attempts"`
	AnalysisPlan    string       `json:"analysis_plan" yaml:"analysis_plan"`
	CanonVersion    string       `json:"canon_version" yaml:"canon_version"`
	Supersedes      *Supersedes  `json:"supersedes,omitempty" yaml:"supersedes,omitempty"`
}

// Subject names the claim and the system under test by identifier and
// digests, never by transmitting prompts or weights.
type Subject struct {
	Name            string          `json:"name" yaml:"name"`
	SystemUnderTest SystemUnderTest `json:"system_under_test" yaml:"system_under_test"`
}

// SystemUnderTest identifies a system. model is a name, not weights.
type SystemUnderTest struct {
	Model        string `json:"model" yaml:"model"`
	PromptSHA256 string `json:"prompt_sha256" yaml:"prompt_sha256"`
	ConfigSHA256 string `json:"config_sha256" yaml:"config_sha256"`
}

// Dataset identifies a local dataset by plimsoll-dataset-v1 digest.
type Dataset struct {
	Path     string `json:"path,omitempty" yaml:"path,omitempty"` // local authoring only; omitted from signed canonical form
	SHA256   string `json:"sha256" yaml:"sha256"`
	N        int    `json:"n" yaml:"n"`
	Sampling string `json:"sampling" yaml:"sampling"`
	HeldOut  bool   `json:"held_out" yaml:"held_out"`
}

// Harness identifies the user's evaluation tool by name, version, and
// config digest. PLIMSOLL does not run the harness.
type Harness struct {
	Tool         string `json:"tool" yaml:"tool"`
	Version      string `json:"version" yaml:"version"`
	ConfigSHA256 string `json:"config_sha256" yaml:"config_sha256"`
}

// Metric is a declared metric. definition_uri points at an external
// definition; this project does not bundle an assessment framework.
type Metric struct {
	ID            string `json:"id" yaml:"id"`
	Name          string `json:"name" yaml:"name"`
	DefinitionURI string `json:"definition_uri" yaml:"definition_uri"`
	Direction     string `json:"direction" yaml:"direction"`
}

// DecisionRule is the sealed predicate. expression is the full rule.
type DecisionRule struct {
	Expression    string `json:"expression" yaml:"expression"`
	PrimaryMetric string `json:"primary_metric" yaml:"primary_metric"`
	Threshold     string `json:"threshold" yaml:"threshold"`
	Comparison    string `json:"comparison" yaml:"comparison"`
	Precision     int    `json:"precision" yaml:"precision"`
}

// Supersedes points at a previous seal. The previous seal is not edited.
type Supersedes struct {
	SealHash string `json:"seal_hash" yaml:"seal_hash"`
	Reason   string `json:"reason" yaml:"reason"`
}

// SignedSeal is a seal plus an Ed25519 signature over its canonical bytes.
type SignedSeal struct {
	Seal      *Seal  `json:"seal"`
	Signature []byte `json:"signature"`
}

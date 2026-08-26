// Copyright 2026 The PLIMSOLL Authors
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

package seal

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/GautamTalksDev/plimsoll/internal/canonical"
	"github.com/GautamTalksDev/plimsoll/internal/expr"
)

var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

var samplingOK = map[string]struct{}{
	"exhaustive": {}, "random": {}, "stratified": {}, "other": {},
}

// Validate checks prereg-v1 semantic rules. Distinct typed errors are
// returned for the conditions listed in the specification checklist.
func (s *Seal) Validate() error {
	if s == nil {
		return fmt.Errorf("seal: nil")
	}
	if s.PlimsollVersion != Version {
		return fmt.Errorf("seal: plimsoll_version %q is not %s", s.PlimsollVersion, Version)
	}
	if s.CanonVersion != CanonVersion {
		return fmt.Errorf("seal: canon_version %q is not %s", s.CanonVersion, CanonVersion)
	}
	if _, err := time.Parse(time.RFC3339, s.CreatedAt); err != nil {
		return fmt.Errorf("seal: created_at: %w", err)
	}
	if !strings.HasSuffix(s.CreatedAt, "Z") {
		return fmt.Errorf("seal: created_at must be UTC with Z suffix")
	}
	if s.Subject.Name == "" || s.Subject.SystemUnderTest.Model == "" {
		return fmt.Errorf("seal: subject name and model are required")
	}
	for _, d := range []string{
		s.Subject.SystemUnderTest.PromptSHA256,
		s.Subject.SystemUnderTest.ConfigSHA256,
		s.Harness.ConfigSHA256,
	} {
		if !digestRe.MatchString(d) {
			return fmt.Errorf("seal: invalid digest %q", d)
		}
	}
	if s.Dataset.SHA256 == "" {
		return &DatasetError{Reason: "missing sha256"}
	}
	if !digestRe.MatchString(s.Dataset.SHA256) {
		return &DatasetError{Reason: "invalid sha256"}
	}
	if s.Dataset.N <= 0 {
		return &DatasetError{Reason: "n <= 0"}
	}
	if _, ok := samplingOK[s.Dataset.Sampling]; !ok {
		return fmt.Errorf("seal: dataset.sampling %q is not allowed", s.Dataset.Sampling)
	}
	if s.Harness.Tool == "" || s.Harness.Version == "" {
		return fmt.Errorf("seal: harness tool and version are required")
	}
	if s.PlannedAttempts < 1 {
		return &PlannedAttemptsError{N: s.PlannedAttempts}
	}
	if s.DecisionRule.Precision < 1 || s.DecisionRule.Precision > 12 {
		return &PrecisionError{Precision: s.DecisionRule.Precision}
	}
	if _, ok := expr.Comparators[s.DecisionRule.Comparison]; !ok {
		return fmt.Errorf("seal: invalid comparison %q", s.DecisionRule.Comparison)
	}
	if _, err := canonical.ParseDecimal(s.DecisionRule.Threshold, s.DecisionRule.Precision); err != nil {
		return fmt.Errorf("seal: threshold: %w", err)
	}
	if len(s.Metrics) < 1 {
		return fmt.Errorf("seal: metrics must be non-empty")
	}
	ids := map[string]struct{}{}
	for _, m := range s.Metrics {
		if m.ID == "" {
			return fmt.Errorf("seal: metric id is required")
		}
		if _, dup := ids[m.ID]; dup {
			return fmt.Errorf("seal: duplicate metric_id %q", m.ID)
		}
		ids[m.ID] = struct{}{}
		if m.Direction != "higher_is_better" && m.Direction != "lower_is_better" {
			return fmt.Errorf("seal: metric %q has invalid direction", m.ID)
		}
	}
	prog, err := expr.ParseExpression(s.DecisionRule.Expression)
	if err != nil {
		return &ExpressionError{Err: err}
	}
	for _, id := range prog.MetricIDs() {
		if _, ok := ids[id]; !ok {
			return &UnknownMetricError{ID: id}
		}
	}
	if _, ok := ids[s.DecisionRule.PrimaryMetric]; !ok {
		return &UnknownMetricError{ID: s.DecisionRule.PrimaryMetric}
	}
	foundPrimary := false
	for _, id := range prog.MetricIDs() {
		if id == s.DecisionRule.PrimaryMetric {
			foundPrimary = true
			break
		}
	}
	if !foundPrimary {
		return &UnknownMetricError{ID: s.DecisionRule.PrimaryMetric}
	}
	if s.Supersedes != nil {
		if !digestRe.MatchString(s.Supersedes.SealHash) {
			return fmt.Errorf("seal: supersedes.seal_hash is invalid")
		}
		if s.Supersedes.Reason == "" {
			return fmt.Errorf("seal: supersedes.reason is required")
		}
	}
	return nil
}

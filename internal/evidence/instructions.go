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

package evidence

// DefaultBrowserVerifierURL is the public browser-based verifier.
const DefaultBrowserVerifierURL = "https://plimsoll.gautamkhosla.com/verify"

// Instructions returns steps a non-user can follow to reproduce verification.
func Instructions(logURL, browserVerifierURL string) []string {
	if browserVerifierURL == "" {
		browserVerifierURL = DefaultBrowserVerifierURL
	}
	steps := []string{
		"PLIMSOLL evidence packs are self-contained records of a pre-registered evaluation claim, " +
			"its transparency-log inclusion proofs, and deterministic verification results (checks V1–V9).",
		"Install the PLIMSOLL CLI from https://github.com/GautamTalksDev/plimsoll/releases " +
			"(or build from source: go install github.com/GautamTalksDev/plimsoll/cmd/plimsoll@latest).",
		"Save the attestation JSON for the attempt you wish to verify (included in this pack under attempts[].attestation).",
	}
	if logURL != "" {
		steps = append(steps,
			"Run: plimsoll verify <attestation.json> --log "+logURL,
			"Compare each V1–V9 check in the CLI output with the verification section in this pack.",
		)
	} else {
		steps = append(steps,
			"Run: plimsoll verify <attestation.json> --log <transparency-log-url>",
			"Compare each V1–V9 check in the CLI output with the verification section in this pack.",
		)
	}
	steps = append(steps,
		"Open the browser verifier (see verify_url in this pack, or "+browserVerifierURL+") and paste the attestation JSON.",
		"Each attempt includes a verify_url link that pre-fills the log endpoint (Rule 9).",
		"Confirm the log public key in this pack matches the key published at <log-url>/key.",
		"Confirm seal and attestation Merkle inclusion proofs verify against the signed checkpoints embedded in this pack.",
		"PLIMSOLL verifies evaluations you ran with your own tools; it does not re-run your harness or receive your dataset.",
	)
	return steps
}

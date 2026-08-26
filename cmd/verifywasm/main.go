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

//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/GautamTalksDev/plimsoll/internal/verify"
)

func main() {
	js.Global().Set("plimsollVerify", js.FuncOf(verifyFunc))
	js.Global().Set("plimsollParseAttestation", js.FuncOf(parseAttestationFunc))
	select {}
}

func verifyFunc(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return errVal("missing attestation JSON")
	}
	report, err := verify.RunBrowser(args[0].String(), strArg(args, 1), strArg(args, 2), boolArg(args, 3))
	if err != nil {
		return errVal(err.Error())
	}
	b, err := json.Marshal(report)
	if err != nil {
		return errVal(err.Error())
	}
	return js.Global().Get("Object").New(map[string]any{
		"ok":     true,
		"report": string(b),
	})
}

func parseAttestationFunc(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return errVal("missing JSON")
	}
	att, env, err := verify.ParseAttestationBytes([]byte(args[0].String()))
	if err != nil {
		return errVal(err.Error())
	}
	out := map[string]any{"ok": true, "seal_hash": att.SealHash, "result_digest": att.ResultDigest}
	if env != nil {
		out["envelope"] = true
	}
	return js.Global().Get("Object").New(out)
}

func strArg(args []js.Value, i int) string {
	if len(args) <= i {
		return ""
	}
	return args[i].String()
}

func boolArg(args []js.Value, i int) bool {
	if len(args) <= i {
		return false
	}
	return args[i].Truthy()
}

func errVal(msg string) js.Value {
	return js.Global().Get("Object").New(map[string]any{"ok": false, "error": msg})
}

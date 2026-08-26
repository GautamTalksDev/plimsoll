#!/usr/bin/env bash
set -euo pipefail

RESULT="${RUNNER_TEMP}/plimsoll-result.json"
OUT="${RUNNER_TEMP}/plimsoll-stdout.json"

ARGS=(attest --seal "${INPUT_SEAL_FILE}" --results "${INPUT_RESULTS_FILE}" --json)
if [[ "${INPUT_PUBLISH}" == "true" ]]; then
  ARGS+=(--publish)
  if [[ -n "${INPUT_LOG_URL:-}" ]]; then
    ARGS+=(--log-url "${INPUT_LOG_URL}")
  elif [[ -n "${INPUT_LOG_PATH:-}" ]]; then
    ARGS+=(--log "${INPUT_LOG_PATH}")
  else
    echo "publish=true requires log-path or log-url" >&2
    exit 1
  fi
fi
if [[ -n "${INPUT_KEY_PATH:-}" ]]; then
  ARGS+=(--key "${INPUT_KEY_PATH}")
fi

set +e
plimsoll "${ARGS[@]}" > "${OUT}" 2> "${RUNNER_TEMP}/plimsoll-stderr.txt"
EXIT=$?
set -e

# plimsoll --json writes JSON to stdout; exit 0/1/2 for PASS/FAIL/INVALID.
python3 - "${OUT}" "${RESULT}" "${EXIT}" <<'PY'
import json, sys
out_path, result_path, exit_s = sys.argv[1:4]
exit_code = int(exit_s)
try:
    with open(out_path) as f:
        data = json.load(f)
except json.JSONDecodeError:
    data = {"verdict": "INVALID", "exit_code": exit_code, "terms": []}
data["exit_code"] = exit_code
fail_on = __import__("os").environ.get("INPUT_FAIL_ON", "non-pass")
verdict = data.get("verdict", "INVALID")
if fail_on == "never":
    data["action_conclusion"] = "success"
elif fail_on == "fail":
    data["action_conclusion"] = "failure" if verdict == "FAIL" else "success"
elif fail_on == "invalid":
    data["action_conclusion"] = "failure" if verdict == "INVALID" else "success"
else:
    data["action_conclusion"] = "success" if verdict == "PASS" else "failure"
with open(result_path, "w") as f:
    json.dump(data, f)
PY

verdict="$(python3 -c "import json; print(json.load(open('${RESULT}'))['verdict'])")"
attempt_no="$(python3 -c "import json; d=json.load(open('${RESULT}')); print(d.get('attempt_no', ''))")"
attestation="$(python3 -c "import json; d=json.load(open('${RESULT}')); print(d.get('attestation', ''))")"

echo "verdict=${verdict}" >> "${GITHUB_OUTPUT}"
echo "exit_code=${EXIT}" >> "${GITHUB_OUTPUT}"
echo "attestation=${attestation}" >> "${GITHUB_OUTPUT}"
echo "attempt_no=${attempt_no}" >> "${GITHUB_OUTPUT}"
conclusion="$(python3 -c "import json; print(json.load(open('${RESULT}'))['action_conclusion'])")"
if [[ "${conclusion}" == "failure" ]]; then
  echo "should_fail=true" >> "${GITHUB_OUTPUT}"
else
  echo "should_fail=false" >> "${GITHUB_OUTPUT}"
fi
cat "${RUNNER_TEMP}/plimsoll-stderr.txt" >&2 || true
exit 0

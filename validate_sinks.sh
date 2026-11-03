#!/usr/bin/env bash
# Validate the meters against the sink ladder, through the normal OSS-Fuzz helper.py flow.
#
# For each Sink* harness:  vulnerable run -> must report a finding
#                          fixed run (-Dsink.safe=true) -> must run to the time limit with no finding
#
# usage:  ./validate_sinks.sh <oss-fuzz-dir> [seconds-per-run] [harness ...]
#   e.g.  ./validate_sinks.sh ~/SPARC/oss-fuzz 120
#         ./validate_sinks.sh ~/SPARC/oss-fuzz 60 SinkSqlStatementFuzzer SinkMvelFuzzer    # quick smoke test
#
# Run build_image + build_fuzzers first. Results: PASS; FAIL (expected finding missing, or a finding
# on a fixed run); WRONG (a vulnerable run found some other bug first); ERROR (fuzzer never started). Logs go to /tmp/validate-<harness>-<mode>.log; meter events to
# <oss-fuzz>/build/out/vulnjava/events-<harness>-<mode>.jsonl(.summary.json).
set -u
OSSFUZZ="${1:?usage: $0 <oss-fuzz-dir> [seconds] [harness ...]}"
T="${2:-120}"
shift $(( $# >= 2 ? 2 : 1 ))
HARNESSES=("$@")
[ ${#HARNESSES[@]} -eq 0 ] && HARNESSES=(SinkZipSlipFuzzer SinkZipBombFuzzer SinkXxeFuzzer SinkMvelFuzzer
                                         SinkSqlStatementFuzzer SinkSqlPreparedFuzzer SinkCertFuzzer SinkTokenFuzzer)
# the finding each vulnerable run must report -- any other finding is WRONG, not PASS
declare -A EXPECT=(
  [SinkZipSlipFuzzer]="File path traversal"
  [SinkZipBombFuzzer]="Decompression bomb"
  [SinkXxeFuzzer]="XML External Entity"
  [SinkMvelFuzzer]="Remote Code Execution"
  [SinkSqlStatementFuzzer]="SQL Injection$"
  [SinkSqlPreparedFuzzer]="SQL Injection in prepared statement text"
  [SinkCertFuzzer]="IllegalArgumentException"
  [SinkTokenFuzzer]="Signature bypass"
)
OUT="$OSSFUZZ/build/out/vulnjava"
cd "$OSSFUZZ" || exit 1
[ -x "$OUT/SinkXxeFuzzer" ] || { echo "no build in $OUT - run build_fuzzers first"; exit 1; }

pass=0; fail=0
printf "\n%-24s %-6s %-5s %s\n" HARNESS MODE OK "WHAT HAPPENED"
for F in "${HARNESSES[@]}"; do
  for MODE in vuln fixed; do
    EV="events-$F-$MODE.jsonl"
    rm -f "$OUT/$EV" "$OUT/$EV.summary.json"
    EXTRA=(); [ "$MODE" = fixed ] && EXTRA=(--additional_jvm_args=-Dsink.safe=true)
    LOG="/tmp/validate-$F-$MODE.log"
    # "--" matters: helper.py would otherwise try to parse the fuzzer flags itself and exit with an error
    CMD=(python3 infra/helper.py run_fuzzer -e METER_EVENTS="/out/$EV" vulnjava "$F" --
         "${EXTRA[@]}" -max_total_time="$T" -print_final_stats=1)
    echo "+ ${CMD[*]}" > "$LOG"
    timeout $((T + 300)) "${CMD[@]}" 2>&1 < /dev/null | tr -d '\r' >> "$LOG"   # docker -t output ends lines with \r
    finding=$(grep -a -m1 -E "^== Java Exception: " "$LOG" | sed -E 's/^== Java Exception: (com\.code_intelligence\.jazzer\.api\.)?//' | cut -c1-90)
    runs=$(grep -a -m1 -oE "stat::number_of_executed_units: *[0-9]+" "$LOG" | grep -oE "[0-9]+$")
    meters=$(python3 -c "import json,sys; c=json.load(open(sys.argv[1]))['counts']; print(', '.join(f'{k.split(\":\",1)[1]}={v}' for k,v in sorted(c.items())))" \
             "$OUT/$EV.summary.json" 2>/dev/null)
    # evidence the fuzzer actually ran (libFuzzer status lines or final stats); otherwise it's a tooling error
    if ! grep -a -qE "INFO: Seed:|#[0-9]+[[:space:]]+(INITED|NEW|REDUCE|pulse|DONE)|stat::number_of_executed_units" "$LOG"; then
      fail=$((fail + 1))
      printf "%-24s %-6s %-5s %s\n" "$F" "$MODE" ERROR "fuzzer never started - last lines of $LOG:"
      tail -n 4 "$LOG" | sed 's/^/                                      | /' | cut -c1-160
      continue
    fi
    if [ "$MODE" = vuln ]; then
      want="${EXPECT[$F]:-.}"
      if [ -z "$finding" ]; then ok=FAIL; what="no finding in ${T}s (${runs:-?} runs)"
      elif echo "$finding" | grep -qE "$want"; then ok=PASS; what="$finding"
      else ok=WRONG; what="found a different bug: $finding (expected: ${want%\$})"
      fi
    else
      [ -z "$finding" ] && ok=PASS || ok=FAIL
      what="${finding:+FALSE POSITIVE: $finding}"; what="${what:-quiet for ${T}s (${runs:-?} runs)}"
    fi
    [ "$ok" = PASS ] && pass=$((pass + 1)) || fail=$((fail + 1))   # WRONG counts as a failure
    printf "%-24s %-6s %-5s %s\n" "$F" "$MODE" "$ok" "$what"
    [ -n "$meters" ] && printf "%-37s meters: %s\n" "" "${meters:0:150}"
  done
done
printf "\n%d passed, %d failed. Logs: /tmp/validate-*.log\n" "$pass" "$fail"
[ "$fail" -eq 0 ]

# vulnjava

A deliberately vulnerable Java/Maven project, built to validate a Jazzer +
ClusterFuzz pipeline end to end before onboarding a real target (MOSIP's
id-repository). Same purpose and shape as the `vulnfuzz` C benchmark: one
dispatcher, six bugs of increasing difficulty, each exercising a different
detection mechanism.

`VulnDispatcher` (under `vulnjava-src/`) is plain Java with zero Jazzer
imports -- it is exactly what a real production module looks like from the
fuzzer's point of view. All Jazzer-specific parsing lives in the harness,
`VulnJavaFuzzer.java`.

## The ladder

| # | Method | Bug class | What crashes | Requires |
|---|--------|-----------|---------------|----------|
| 1 | `level1` | Unchecked index | `ArrayIndexOutOfBoundsException` | Any index > 15. Found in seconds. |
| 2 | `level2` | Off-by-one copy loop | `ArrayIndexOutOfBoundsException` | `len` landing at/past a boundary value. |
| 3 | `level3` | 32-bit multiplication overflow | `ArrayIndexOutOfBoundsException` | `count` in the narrow band where `count * 40` wraps negative (~53.7M+). Deliberately does *not* allocate a `count`-sized array -- see the comment in the source for why. |
| 4 | `level4` | Use-after-close | `NullPointerException` | A specific 3-step sequence (OPEN, then CLOSE, then USE) on the *same* handle id. |
| 5 | `level5` | Exact string comparison gate | `IllegalStateException` | Guessing the 7-byte string `"OPEN_ME"`. Tests Jazzer's automatic value-profiling hooks on `String.equals` -- the JVM analogue of AFL++'s CmpLog. Deliberately excluded from the seed corpus. |
| 6 | `level6` | OS command injection | No exception at all | Fuzzer-controlled data flowing into a shell-interpreted `ProcessBuilder` call. The finding comes entirely from Jazzer's *built-in* `OsCommandInjection` sanitizer, not from anything this code throws -- this is the one level that tests a completely different detection path than 1-5. |

Levels 1-4 test the basic pipeline (does ClusterFuzz see uncaught exceptions
as crashes at all). Level 5 tests comparison-guided mutation. Level 6 tests
whether Jazzer's security sanitizers are actually wired up and active --
none of your existing AFL++/libFuzzer C jobs have an equivalent of this, so
it's the one result that's genuinely new information about the setup.

## Layout

```
vulnjava/
├── Dockerfile                       OSS-Fuzz-format, FROM base-builder-jvm
├── build.sh                         mvn package -> javac harness -> wrapper script
├── project.yaml                     language: jvm, engine: libfuzzer, sanitizer: address
├── VulnJavaFuzzer.java              the only file that imports Jazzer
├── VulnJavaFuzzer_seed_corpus.zip   12 short, harmless, varied-length seeds
└── vulnjava-src/                    the "upstream" project, as if git-cloned
    ├── pom.xml
    └── src/main/java/com/sparc/vulnjava/VulnDispatcher.java
```

## Testing locally, before ClusterFuzz

Using your existing OSS-Fuzz checkout and `infra/helper.py` flow (the same
one you used for `vulnfuzz`):

```bash
# Drop this directory in as a project (symlink, same pattern as before).
ln -s /path/to/vulnjava $OSS_FUZZ_DIR/projects/vulnjava

cd $OSS_FUZZ_DIR

# Build the image and the fuzzer. --sanitizer=address is mostly a formality
# here (see the note in the previous message on what "sanitizers" mean for
# jvm-language projects) but the job template expects a value.
python3 infra/helper.py build_image vulnjava
python3 infra/helper.py build_fuzzers --sanitizer=address vulnjava

# Fuzz locally, reading from the seed corpus. Ctrl-C to stop -- run it long
# enough to see all six levels fall (levels 1-4 should be seconds to low
# minutes; 5 and 6 may take longer since they need comparison-guided
# mutation or specific structural input, not brute force).
python3 infra/helper.py run_fuzzer vulnjava VulnJavaFuzzer

# Once you have a saved crash file, replay it directly:
python3 infra/helper.py reproduce vulnjava VulnJavaFuzzer <path-to-testcase>
```

What you should see for each level: a Java stack trace printed to the
console (not an ASan report), plus two files written to your working
directory -- `crash-<sha1>` (raw input bytes, same convention as libFuzzer)
and `Crash_<sha1>.java`, a generated standalone reproducer with a `main()`
that replays the crash without Jazzer at all. Level 6's "crash" will look
different from the other five: no Java exception in the trace, just Jazzer
reporting an `OS Command Injection` finding directly.

## A safety note on level 6

The injected command is a harmless `echo`, and it's real shell-interpreted
`ProcessBuilder`/`sh -c` code, so a sufficiently adversarial mutation could
in principle produce a longer-running or resource-heavy child command
during fuzzing. This is already contained the same way your other fuzz jobs
are -- run inside a Docker container locally, and inside an ephemeral GCP
Batch job once it's on your bots -- so nothing here needs a separate
sandbox. Worth knowing about if you ever see a fuzzing session's system
resource usage spike unexpectedly during this specific target.

## Once all six are found locally

Package `$OUT` the same way you already do for CUSTOM_BINARY uploads, and
register the ClusterFuzz job with `libfuzzer` (not `afl`) somewhere in its
name -- there's no AFL job type for this, per the mechanism differences
covered in the previous message. Confirm `jazzer_driver` runs on your bot
with a quick `ldd` before trusting it there, the same check you ran for the
Rust build -- base-builder-jvm and your bot image both trace back to Ubuntu
20.04, so this is a formality here rather than the real risk it was for a
hand-built native binary, but worth confirming once rather than assuming.

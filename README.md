# vulnjava

A deliberately vulnerable Java/Maven project, built to validate a Jazzer +
ClusterFuzz pipeline end to end before onboarding a real target (MOSIP's
id-repository). Same purpose and shape as the `vulnfuzz` C benchmark: one
dispatcher, eight bugs of increasing difficulty, each exercising a different
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
| 6 | `level6` | OS command injection | No exception at all | Fuzzer-controlled data flowing into a shell-interpreted `ProcessBuilder` call. Caught entirely by Jazzer's *built-in* `OsCommandInjection` sanitizer. |
| 7 | `level7` | Insecure deserialization | No exception, if it works | Untrusted bytes into `ObjectInputStream.readObject()`. Caught by Jazzer's *built-in* `Deserialization` sanitizer. Needs a real gadget-bearing class on the classpath and a validly-serialized seed -- see "Level 7 setup" below, this one needs a one-time step before it's findable at all. |
| 8 | `level8` | Catastrophic regex backtracking | A hang/timeout | A long-enough run of `'a'` characters against a fixed pattern. See "A note on level 8" -- this is *not* the textbook evil-regex example, on purpose. |

Levels 1-4 test the basic pipeline (does ClusterFuzz see uncaught exceptions
as crashes at all). Level 5 tests comparison-guided mutation. Levels 6 and 7
test whether Jazzer's security sanitizers are wired up and active -- none of
your existing AFL++/libFuzzer C jobs have an equivalent of either. Level 8
tests hang detection, a third mechanism again, distinct from both exceptions
and sanitizer hooks.

## Layout

```
vulnjava/
├── Dockerfile                       OSS-Fuzz-format, FROM base-builder-jvm
├── build.sh                         mvn package -> javac harness -> wrapper script (unchanged by levels 7-8)
├── project.yaml                     language: jvm, engine: libfuzzer, sanitizer: address
├── VulnJavaFuzzer.java              the only file that imports Jazzer
├── VulnJavaFuzzer_seed_corpus.zip   12 short, harmless, varied-length seeds
├── tools/
│   └── GenerateDeserializationSeed.java   one-time generator for level 7's seed, see below
└── vulnjava-src/                    the "upstream" project, as if git-cloned
    ├── pom.xml                      now also pulls in commons-collections:3.2.1 + maven-shade-plugin
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
# enough to see all eight levels fall. Levels 1-4 should be seconds to low
# minutes; 5, 6, 8 may take longer since they need comparison-guided
# mutation, specific structural input, or a long run of one byte value,
# not brute force. Level 7 will not be found at all without the seed from
# "Level 7 setup" below.
python3 infra/helper.py run_fuzzer vulnjava VulnJavaFuzzer

# Once you have a saved crash file, replay it directly:
python3 infra/helper.py reproduce vulnjava VulnJavaFuzzer <path-to-testcase>
```

What you should see for each level: a Java stack trace printed to the
console (not an ASan report), plus two files written to your working
directory -- `crash-<sha1>` (raw input bytes, same convention as libFuzzer)
and `Crash_<sha1>.java`, a generated standalone reproducer with a `main()`
that replays the crash without Jazzer at all. Levels 6 and 7 look different
from the rest: no Java exception in the trace, just Jazzer reporting an
`OS Command Injection` or `Deserialization` finding directly. Level 8 looks
different again: a timeout/hang report rather than a stack trace at all.

## Level 7 setup

Deserialization is a genuinely different kind of test than the other seven,
and it's worth understanding why before you run it. Java's serialization
format is structured (magic bytes, class descriptors, field data) -- a
byte-fuzzer starting from nothing will essentially never construct a valid
stream through mutation alone, let alone one that references a dangerous
class. So unlike every other level, this one needs a real, validly-
serialized payload provided as a seed up front; mutation only takes over
from there.

`pom.xml` now pulls in `commons-collections:3.2.1` -- deliberately the old,
publicly-known-vulnerable release, used here for exactly the reason
security tooling always uses it: it's a real, well-documented gadget chain
to give Jazzer's sanitizer something genuine to detect, the same way an
EICAR file gives antivirus software something to detect. `VulnDispatcher`
itself never imports these classes; they only need to be resolvable at
runtime, which the `maven-shade-plugin` addition to `pom.xml` takes care of
by bundling them into `vulnjava.jar`.

`tools/GenerateDeserializationSeed.java` builds the actual payload -- the
standard "CC6" gadget chain (the one specifically known for working across
a wide range of JDK versions, unlike the older CC1 chain which an Oracle
patch broke on JDK 8u71+), with the final command replaced by the harmless
`true`. Run it once, with commons-collections on the classpath (Maven
already downloaded it into your local repo when you built `vulnjava-src`):

```bash
CC=$HOME/.m2/repository/commons-collections/commons-collections/3.2.1/commons-collections-3.2.1.jar
cd tools
javac -cp "$CC" GenerateDeserializationSeed.java
java -cp ".:$CC" GenerateDeserializationSeed cc6_seed.bin
```

It prints its own sanity check (deserializes what it just wrote, in the
same JVM, and confirms it completes without error). Once you've confirmed
that, drop `cc6_seed.bin` into the corpus you point `run_fuzzer` at, or add
it to `VulnJavaFuzzer_seed_corpus.zip` before rebuilding.

**Honest caveat**: I built this generator against the well-documented public
CC6 construction from memory, but I could not compile or run it myself --
my environment has no route to Maven Central to fetch commons-collections.
Everything else in this project I compiled and exercised directly; this is
the one piece to sanity-check yourself before trusting it, via the printed
self-check above.

## A note on level 8

The obvious choice here would have been the textbook "evil regex",
`(a+)+` matched against a run of `a`s with a trailing mismatch. I tried it
first, and it does **not** hang -- I checked empirically across JDK 8, 11,
and 21. It blows up badly on JDK 8 (14+ seconds at just 30 characters), but
OpenJDK hardened `java.util.regex` against this exact pattern shape
somewhere between 8 and 11, and it's now instant on every later JDK I
tested, including several other "classic" variants of the same idea
(alternation-based, character-class-based). A fair number of ReDoS
write-ups you'll find online use this example without mentioning it's
stale on modern JDKs.

What still reliably blows up on every JDK I tested, including 21, is
several independent `(a+)` groups in a row competing for the same pool of
characters -- there's no redundant-quantifier structure for the engine to
optimize away. That's what `level8` actually uses. Worth keeping in mind
for MOSIP too: a validation regex with one obviously-nested quantifier
might already be safe on whatever JDK it runs on, but one built by
concatenating several separately-quantified field patterns in sequence
(a common shape for structured-ID validation) is a different story.

## A safety note on levels 6 and 7

Level 6's injected command is a harmless `echo`; level 7's gadget chain
runs the harmless `true`. Both are real shell-interpreted/reflective code
paths, though, so a sufficiently adversarial mutation could in principle
produce a longer-running or resource-heavy child process during fuzzing.
This is already contained the same way your other fuzz jobs are -- run
inside a Docker container locally, and inside an ephemeral GCP Batch job
once it's on your bots -- so nothing here needs a separate sandbox. Worth
knowing about if you ever see a fuzzing session's system resource usage
spike unexpectedly during either of these two targets.

## Once all eight are found locally

Package `$OUT` the same way you already do for CUSTOM_BINARY uploads, and
register the ClusterFuzz job with `libfuzzer` (not `afl`) somewhere in its
name -- there's no AFL job type for this, per the mechanism differences
covered in the previous message. Confirm `jazzer_driver` runs on your bot
with a quick `ldd` before trusting it there, the same check you ran for the
Rust build -- base-builder-jvm and your bot image both trace back to Ubuntu
20.04, so this is a formality here rather than the real risk it was for a
hand-built native binary, but worth confirming once rather than assuming.

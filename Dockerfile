# OSS-Fuzz-format Dockerfile for vulnjava.
#
# base-builder-jvm already ships OpenJDK, Jazzer's driver/agent/api jars, and
# the env vars build.sh relies on ($OUT, $SRC, $JAZZER_API_PATH,
# $JVM_LD_LIBRARY_PATH). It descends from the same Ubuntu 20.04 lineage as
# your ClusterFuzz bot image, so jazzer_driver built here should run on your
# bots without a separate glibc check -- worth confirming once, but this is
# not the AFL++/Rust situation where you had to pin a container yourself.
FROM gcr.io/oss-fuzz-base/base-builder-jvm

RUN apt-get update && apt-get install -y maven

# "Upstream" project source, kept in its own subdirectory the way a real
# git-cloned project would be.
COPY vulnjava-src $SRC/vulnjava

# OSS-Fuzz plumbing: build script, fuzz harness, seed corpus -- these sit at
# $SRC root, sibling to the project source, matching google/oss-fuzz's own
# json-sanitizer example project layout.
COPY build.sh VulnJavaFuzzer.java VulnJavaFuzzer_seed_corpus.zip $SRC/

WORKDIR $SRC/vulnjava

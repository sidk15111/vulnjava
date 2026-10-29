#!/bin/bash -eu
#
# build.sh for vulnjava.
#
# Runs inside gcr.io/oss-fuzz-base/base-builder-jvm with WORKDIR set to
# $SRC/vulnjava (the "upstream" Maven project, copied there by the
# Dockerfile). $SRC, $OUT, $JAZZER_API_PATH and $JVM_LD_LIBRARY_PATH are all
# provided by the base image.

# Seed corpus (matched to the fuzzer by name).
cp $SRC/VulnJavaFuzzer_seed_corpus.zip $OUT/ 2>/dev/null || true

# --- Step 1: build the library jar with Maven. -----------------------------
mvn package
CURRENT_VERSION=$(mvn org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
  -Dexpression=project.version -q -DforceStdout)
cp "target/vulnjava-$CURRENT_VERSION.jar" $OUT/vulnjava.jar
PROJECT_JARS="vulnjava.jar"

# --- Step 1b: build the meter hooks (sink ladder only). ---------------------
mkdir -p $SRC/meters/build
javac -cp $JAZZER_API_PATH -d $SRC/meters/build $SRC/meters/src/sparc/meters/*.java
cp -r $SRC/meters/src/META-INF $SRC/meters/build/
(cd $SRC/meters/build && jar cf $OUT/meters.jar sparc META-INF)
METER_HOOKS="sparc.meters.ArchiveHooks:sparc.meters.XmlHooks:sparc.meters.ExpressionHooks:sparc.meters.SqlHooks:sparc.meters.CryptoHooks"
cp $SRC/Sink*.dict $SRC/Sink*.options $SRC/Sink*_seed_corpus.zip $OUT/ 2>/dev/null || true

# --- Step 2: compile the fuzz harness against the library jar + Jazzer API. -
BUILD_CLASSPATH=$(echo $PROJECT_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH
RUNTIME_CLASSPATH=$(echo $PROJECT_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

for fuzzer in $(find $SRC -maxdepth 1 -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH -d $SRC $fuzzer
  cp $SRC/$fuzzer_basename.class $OUT/

  # Sink-ladder harnesses run with the meter hooks; the original ladder runs without them.
  EXTRA_CP=""; HOOK_ARGS=""
  case $fuzzer_basename in Sink*)
    EXTRA_CP=":\$this_dir/meters.jar"
    HOOK_ARGS="--custom_hooks=$METER_HOOKS"
  esac

  echo "#!/bin/bash
this_dir=\$(dirname \"\$0\")
LD_LIBRARY_PATH=\"\$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH$EXTRA_CP \
--target_class=$fuzzer_basename $HOOK_ARGS \
--jvm_args=\"-Xmx2048m:-Xss1024k:-Djava.awt.headless=true\" \
\$@" > $OUT/$fuzzer_basename
  chmod +x $OUT/$fuzzer_basename
done

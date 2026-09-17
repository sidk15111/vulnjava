package com.sparc.vulnjava;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.regex.Pattern;

/**
 * VulnDispatcher: a Java analogue of the "vulnfuzz" C benchmark.
 *
 * Eight intentionally vulnerable methods, each exercising a different bug
 * class and a different detection mechanism. Nothing in this file imports
 * Jazzer or knows it is being fuzzed -- all the fuzzer-specific parsing
 * lives in the harness (VulnJavaFuzzer.java), exactly the shape a real
 * production module's code stays in when you fuzz it.
 *
 * Difficulty ladder:
 *   1. Trivial unchecked array index            -> ArrayIndexOutOfBoundsException
 *   2. Off-by-one copy loop                      -> ArrayIndexOutOfBoundsException, needs a boundary value
 *   3. 32-bit multiplication overflow            -> ArrayIndexOutOfBoundsException, needs the overflow band
 *   4. Stateful handle table (open/close/use)    -> NullPointerException, needs a specific 3-step sequence
 *   5. Exact string comparison gate              -> IllegalStateException, tests Jazzer's comparison hooks
 *   6. Unsanitized input into a shell command    -> caught by Jazzer's built-in OS Command Injection sanitizer,
 *                                                    not by any exception thrown here
 *   7. Untrusted bytes into ObjectInputStream    -> caught by Jazzer's built-in Deserialization sanitizer;
 *                                                    needs a real gadget-bearing class on the classpath and a
 *                                                    validly-serialized seed (see README, "Level 7 setup")
 *   8. Catastrophic-backtracking regex           -> a hang/timeout, not an exception -- a third detection
 *                                                    mechanism again, distinct from both 1-5 and 6-7
 */
public class VulnDispatcher {

    private VulnDispatcher() {}

    /** Level 1: trivial unchecked index into a fixed-size buffer. */
    public static void level1(int index) {
        byte[] buffer = new byte[16];
        buffer[index] = 0x01;
    }

    /** Level 2: off-by-one copy. Crashes only when len lands on/after the boundary. */
    public static void level2(int len, byte[] src) {
        byte[] dst = new byte[16];
        // BUG: should be `i < len`. As written, len == dst.length lets the loop
        // write one slot past the end of dst.
        for (int i = 0; i <= len && i < src.length; i++) {
            dst[i] = src[i];
        }
    }

    /**
     * Level 3: record-count * record-size overflows 32-bit int arithmetic.
     * Deliberately does NOT allocate an array of `totalSize` bytes -- doing
     * that would mean legitimately-large-but-not-yet-overflowing counts
     * request near-2GB allocations and get killed by the JVM heap limit
     * before ever reaching the overflow band, muddying the finding with
     * unrelated OutOfMemoryErrors. Instead, the wrapped value is trusted as
     * an index into a small fixed header, which is cheap regardless of
     * count and only misbehaves in the genuine overflow band.
     */
    public static void level3(int count) {
        int recordSize = 40;
        int totalSize = count * recordSize; // wraps around exactly like C, no exception on overflow itself
        int[] header = new int[4];
        if (totalSize < 0) {
            // BUG: the overflow was already trusted as a valid, small index.
            header[totalSize] = 1; // ArrayIndexOutOfBoundsException, only reachable via genuine overflow
        }
    }

    /**
     * Level 4: a tiny stateful handle table. OPEN allocates a handle, CLOSE
     * releases it, USE writes through it. The bug: USE doesn't check whether
     * the handle was already closed, only whether it looks non-null right
     * now -- a use-after-close, the JVM analogue of a use-after-free.
     * Requires OPEN, then CLOSE, then USE on the *same* handle id, in that
     * order, to actually crash.
     */
    public static void level4(int[] subOps, int[] handleIds) {
        final int slots = 8;
        byte[][] handles = new byte[slots][];
        boolean[] everOpened = new boolean[slots];

        int steps = Math.min(subOps.length, handleIds.length);
        for (int i = 0; i < steps; i++) {
            int handleId = Math.floorMod(handleIds[i], slots);
            int op = Math.floorMod(subOps[i], 3);
            switch (op) {
                case 0: // OPEN
                    handles[handleId] = new byte[4];
                    everOpened[handleId] = true;
                    break;
                case 1: // CLOSE
                    handles[handleId] = null;
                    break;
                case 2: // USE
                    if (!everOpened[handleId]) {
                        break; // never opened -- harmless no-op
                    }
                    handles[handleId][0] = 1; // NullPointerException if this handle was CLOSEd first
                    break;
                default:
                    break;
            }
        }
    }

    /**
     * Level 5: gated behind an exact string match. Nothing here is "hard" for
     * a human, but a fuzzer has to blindly guess a 7-character string out of
     * 256^7 possibilities unless something guides it -- which is exactly what
     * Jazzer's automatic hooks on String.equals are for.
     */
    public static void level5(String tag) {
        if ("OPEN_ME".equals(tag)) {
            throw new IllegalStateException("reached the magic branch");
        }
    }

    /**
     * Level 6: fuzzer-controlled data flows unsanitized into a shell-
     * interpreted command. This is the one level with no thrown exception at
     * all when it "succeeds" -- the finding comes entirely from Jazzer's
     * built-in OsCommandInjection sanitizer watching the process launch.
     */
    public static void level6(String userInput) throws java.io.IOException {
        new ProcessBuilder("/bin/sh", "-c", "echo " + userInput).start();
    }

    /**
     * Level 7: fuzzer-controlled bytes fed straight into Java's native
     * deserialization. This method itself has zero dependency on any
     * "gadget" library -- readObject() will resolve whatever class the
     * stream names, using whatever is on the runtime classpath.
     *
     * That's also why this level can't be found by mutation alone: Java's
     * serialization format is structured (magic bytes, class descriptors,
     * field data) and a byte-fuzzer starting from nothing will essentially
     * never construct a valid stream, let alone one that references a
     * dangerous class. It needs a real serialized payload as a seed -- see
     * README, "Level 7 setup", for the one-time step that generates one
     * using a known-vulnerable commons-collections gadget chain.
     */
    public static void level7(byte[] serializedBytes) throws java.io.IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedBytes))) {
            ois.readObject();
        }
    }

    /**
     * Level 8: catastrophic regex backtracking. Deliberately NOT the
     * textbook "(a+)+" nested-quantifier example -- verified empirically
     * that modern OpenJDK (11 and later) has hardened java.util.regex
     * against that exact shape, so it no longer hangs at all. This pattern
     * -- several independent (a+) groups in a row, all competing for the
     * same pool of characters -- still causes genuine combinatorial
     * backtracking on every JDK tested (8, 11, 21), because there's no
     * redundant-quantifier structure for the engine to simplify away.
     * The finding here is a hang/timeout, not an exception -- a third
     * detection mechanism, distinct from both the exceptions in 1-5 and
     * the built-in sanitizers in 6-7.
     */
    private static final Pattern CATASTROPHIC_PATTERN =
            Pattern.compile("(a+)(a+)(a+)(a+)(a+)(a+)(a+)(a+)(a+)(a+)b");

    public static void level8(String input) {
        CATASTROPHIC_PATTERN.matcher(input).matches();
    }
}

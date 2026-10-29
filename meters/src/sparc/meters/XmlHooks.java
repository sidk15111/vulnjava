package sparc.meters;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

/**
 * XML sinks (CBEFF and other XML parsed from outside input).
 *
 * Meters:   xml.parse              - a parse/unmarshal call was reached; arg = system id / file, if any
 *           xml.parser.unhardened  - signal: a DocumentBuilder was built with DOCTYPEs allowed
 * Detects:  XXE - an external entity was resolved. The canary file /tmp/jazzer-xxe holds a unique
 *           string; the dictionary offers  <!DOCTYPE r [<!ENTITY x SYSTEM "file:///tmp/jazzer-xxe">]>
 *           and &x;. Reported if that string shows up in a parsed Document, or if any code opens a
 *           URL naming the canary (covers SAX/JAXB/StAX too).
 */
public final class XmlHooks {
    static final String CANARY_CONTENT = "JAZZER_XXE_CANARY_7f3a";
    static final String CANARY_NAME = "jazzer-xxe";

    static {
        Path p = Paths.get("/tmp", CANARY_NAME);
        Meter.BUSY.set(true);
        try {
            if (!Files.exists(p)) Files.writeString(p, CANARY_CONTENT, StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.err.println("[meter] cannot create XXE canary " + p + ": " + e);
        } finally {
            Meter.BUSY.set(false);
        }
    }

    private XmlHooks() {}

    @MethodHook(type = HookType.AFTER, targetClassName = "javax.xml.parsers.DocumentBuilderFactory", targetMethod = "newDocumentBuilder")
    public static void builderCreated(MethodHandle method, Object self, Object[] args, int hookId, Object ret) {
        if (!(self instanceof DocumentBuilderFactory)) return;
        DocumentBuilderFactory f = (DocumentBuilderFactory) self;
        boolean doctypeDisallowed = feature(f, "http://apache.org/xml/features/disallow-doctype-decl");
        boolean externalEntities = !featureIsFalse(f, "http://xml.org/sax/features/external-general-entities");
        if (!doctypeDisallowed && externalEntities && f.isExpandEntityReferences()) {
            Meter.signal("xml.parser.unhardened", "DOCTYPE allowed, external entities on", hookId);
        }
    }

    @MethodHook(type = HookType.BEFORE, targetClassName = "javax.xml.parsers.DocumentBuilder", targetMethod = "parse")
    @MethodHook(type = HookType.BEFORE, targetClassName = "javax.xml.parsers.SAXParser", targetMethod = "parse")
    @MethodHook(type = HookType.BEFORE, targetClassName = "org.xml.sax.XMLReader", targetMethod = "parse")
    @MethodHook(type = HookType.BEFORE, targetClassName = "javax.xml.bind.Unmarshaller", targetMethod = "unmarshal")
    @MethodHook(type = HookType.BEFORE, targetClassName = "jakarta.xml.bind.Unmarshaller", targetMethod = "unmarshal")
    @MethodHook(type = HookType.BEFORE, targetClassName = "javax.xml.stream.XMLInputFactory", targetMethod = "createXMLStreamReader")
    public static void parse(MethodHandle method, Object self, Object[] args, int hookId) {
        String arg = null;
        if (args.length > 0) {
            if (args[0] instanceof String) arg = (String) args[0];
            else if (args[0] instanceof File) arg = ((File) args[0]).getPath();
        }
        Meter.reached("xml.parse", arg, hookId);
    }

    @MethodHook(type = HookType.AFTER, targetClassName = "javax.xml.parsers.DocumentBuilder", targetMethod = "parse")
    public static void parsed(MethodHandle method, Object self, Object[] args, int hookId, Object ret) {
        if (ret instanceof Document) {
            Document d = (Document) ret;
            String text = d.getDocumentElement() == null ? null : d.getDocumentElement().getTextContent();
            if (text != null && text.contains(CANARY_CONTENT)) report("the canary file's content appeared in the parsed document");
        }
    }

    @MethodHook(type = HookType.BEFORE, targetClassName = "java.net.URL", targetMethod = "openConnection")
    @MethodHook(type = HookType.BEFORE, targetClassName = "java.net.URL", targetMethod = "openStream")
    public static void urlOpen(MethodHandle method, Object self, Object[] args, int hookId) {
        if (self != null && self.toString().contains(CANARY_NAME)) report("the parser opened " + self);
    }

    private static void report(String how) {
        Jazzer.reportFindingFromHook(new FuzzerSecurityIssueHigh(
                "XML External Entity (XXE): " + how + " - external entities are resolved for outside input"));
    }

    private static boolean feature(DocumentBuilderFactory f, String name) {
        try { return f.getFeature(name); } catch (Exception e) { return false; }
    }

    private static boolean featureIsFalse(DocumentBuilderFactory f, String name) {
        try { return !f.getFeature(name); } catch (Exception e) { return false; }
    }
}

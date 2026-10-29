package sparc.meters;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.Jazzer;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.net.spi.URLStreamHandlerProvider;

/**
 * XXE detector that works for every XML API (DOM, SAX, JAXB, StAX) without instrumenting the JDK:
 * registers the URL scheme "jazzerxxe" through META-INF/services. A parser that resolves the
 * dictionary's external entity  <!ENTITY x SYSTEM "jazzerxxe://canary">  must open that URL,
 * which reports the finding. Nothing else in a program uses this scheme, so there are no false positives.
 */
public class XxeUrlProvider extends URLStreamHandlerProvider {
    @Override
    public URLStreamHandler createURLStreamHandler(String protocol) {
        if (!"jazzerxxe".equals(protocol)) return null;
        return new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(URL u) throws IOException {
                Jazzer.reportFindingFromHook(new FuzzerSecurityIssueHigh(
                        "XML External Entity (XXE): the parser resolved an external entity (" + u
                                + ") from outside input"));
                throw new IOException("jazzerxxe canary");
            }
        };
    }
}

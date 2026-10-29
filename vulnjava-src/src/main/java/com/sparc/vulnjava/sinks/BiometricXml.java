package com.sparc.vulnjava.sinks;

import java.io.IOException;
import java.io.StringReader;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * Sink S3: biometric records arrive as CBEFF-style XML (a BIR element per record), as in MOSIP
 * packets and auth requests. Entry -> check it looks like CBEFF -> build parser -> parse.
 *
 *   S3 XXE: the DocumentBuilderFactory is left at its defaults, so a DOCTYPE with an external
 *           entity is resolved and the file's content is pulled into the document.
 *
 * Passing safe=true disallows DOCTYPE declarations, the standard fix.
 */
public final class BiometricXml {
    private BiometricXml() {}

    /** Entry: number of BIR records in the document, and the text of the first one. */
    public static String firstRecordText(String cbeffXml, boolean safe)
            throws ParserConfigurationException, SAXException, IOException {
        if (cbeffXml == null || !cbeffXml.contains("<BIR")) {
            throw new IllegalArgumentException("not a CBEFF document");
        }
        Document doc = parse(cbeffXml, safe);
        NodeList birs = doc.getElementsByTagName("BIR");
        return birs.getLength() == 0 ? null : birs.item(0).getTextContent();
    }

    static Document parse(String xml, boolean safe) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();   // BUG (S3): default settings
        if (safe) {
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        }
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new InputSource(new StringReader(xml)));
    }
}

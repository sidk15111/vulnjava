package com.sparc.vulnjava.sinks;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Sinks S1 and S2: a registration "packet" is a zip archive, the way MOSIP packets are.
 * Shape mirrors packet-manager: entry (storeDocuments / readDocument) -> validate -> extract/read.
 *
 *   S1 zip slip:            extractTo builds the output path from the entry name without
 *                           normalising it, so "../x" escapes the target directory.
 *   S2 decompression bomb:  readEntry inflates an entry fully into memory with no size limit.
 *
 * Passing safe=true runs the fixed version of each.
 */
public final class PacketArchive {
    static final int MAX_PACKET_BYTES = 1 << 20;
    static final int MAX_DOCUMENT_BYTES = 1 << 20;   // well under the bomb meter threshold (16 MB)
    static final int COPY_LIMIT = 1 << 16;

    private PacketArchive() {}

    /** S1 entry: store every document of a packet under baseDir. Returns the number written. */
    public static int storeDocuments(byte[] packet, File baseDir, boolean safe) throws IOException {
        validate(packet);
        return safe ? extractToSafe(packet, baseDir) : extractTo(packet, baseDir);
    }

    /** S2 entry: return one document's bytes from a packet, or null if absent. */
    public static byte[] readDocument(byte[] packet, String name, boolean safe) throws IOException {
        validate(packet);
        return readEntry(packet, name, safe);
    }

    static void validate(byte[] packet) {
        if (packet == null || packet.length < 4 || packet[0] != 'P' || packet[1] != 'K') {
            throw new IllegalArgumentException("not a packet archive");
        }
        if (packet.length > MAX_PACKET_BYTES) {
            throw new IllegalArgumentException("packet too large");
        }
    }

    static int extractTo(byte[] zip, File dir) throws IOException {
        int written = 0;
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zip))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                File out = new File(dir, e.getName());          // BUG (S1): entry name used as-is
                if (e.isDirectory()) {
                    out.mkdirs();
                    continue;
                }
                File parent = out.getParentFile();
                if (parent != null) parent.mkdirs();
                writeLimited(zis, out);
                written++;
            }
        }
        return written;
    }

    static int extractToSafe(byte[] zip, File dir) throws IOException {
        String root = dir.getCanonicalPath() + File.separator;
        int written = 0;
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zip))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                File out = new File(dir, e.getName());
                if (!out.getCanonicalPath().startsWith(root)) {
                    throw new IOException("entry outside target directory: " + e.getName());
                }
                if (e.isDirectory()) {
                    out.mkdirs();
                    continue;
                }
                File parent = out.getParentFile();
                if (parent != null) parent.mkdirs();
                writeLimited(zis, out);
                written++;
            }
        }
        return written;
    }

    /** Copies at most COPY_LIMIT bytes, so S1 tests path handling only, not S2. */
    private static void writeLimited(ZipInputStream zis, File out) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write(zis.readNBytes(COPY_LIMIT));
        }
    }

    static byte[] readEntry(byte[] zip, String name, boolean safe) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zip))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (!e.getName().equals(name)) continue;
                if (!safe) {
                    return zis.readAllBytes();                    // BUG (S2): no size limit
                }
                byte[] data = zis.readNBytes(MAX_DOCUMENT_BYTES + 1);
                if (data.length > MAX_DOCUMENT_BYTES) throw new IOException("document too large");
                return data;
            }
        }
        return null;
    }
}

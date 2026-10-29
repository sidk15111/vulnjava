package com.sparc.vulnjava.sinks;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Sinks S5a/S5b: device search over a real (in-memory H2) database, the shape of MOSIP's
 * masterdata/PMS search endpoints. Entry -> validate length -> build query -> execute.
 *
 *   S5a SQL injection via Statement:            caught by Jazzer's built-in SqlInjection detector.
 *   S5b SQL injection in prepareStatement text: concatenated into the text, not bound -- the
 *       built-in detector doesn't see this one; the SqlHooks meter does.
 *
 * Passing safe=true binds the value as a parameter.
 */
public final class DeviceRepository {
    private static Connection connection;

    private DeviceRepository() {}

    static synchronized Connection db() throws SQLException {
        if (connection == null) {
            connection = DriverManager.getConnection("jdbc:h2:mem:devices;DB_CLOSE_DELAY=-1");
            try (Statement st = connection.createStatement()) {
                st.execute("CREATE TABLE IF NOT EXISTS device(id INT, name VARCHAR(64), zone VARCHAR(16))");
                st.execute("DELETE FROM device");
                st.execute("INSERT INTO device VALUES (1,'scanner-01','north'),(2,'scanner-02','south'),(3,'camera-01','north')");
            }
        }
        return connection;
    }

    /** S5a entry: count devices with this name. */
    public static int countByName(String name, boolean safe) throws SQLException {
        validate(name);
        if (safe) return countBound("SELECT COUNT(*) FROM device WHERE name = ?", name);
        try (Statement st = db().createStatement();
             ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM device WHERE name = '" + name + "'")) {   // BUG (S5a)
            return rs.next() ? rs.getInt(1) : 0;
        }
    }

    /** S5b entry: count devices in this zone. */
    public static int countByZone(String zone, boolean safe) throws SQLException {
        validate(zone);
        if (safe) return countBound("SELECT COUNT(*) FROM device WHERE zone = ?", zone);
        try (PreparedStatement ps = db().prepareStatement(
                "SELECT COUNT(*) FROM device WHERE zone = '" + zone + "'");                              // BUG (S5b)
             ResultSet rs = ps.executeQuery()) {
            return rs.next() ? rs.getInt(1) : 0;
        }
    }

    static void validate(String value) {
        if (value == null || value.isEmpty() || value.length() > 64) {
            throw new IllegalArgumentException("bad search value");
        }
    }

    private static int countBound(String sql, String value) throws SQLException {
        try (PreparedStatement ps = db().prepareStatement(sql)) {
            ps.setString(1, value);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        }
    }
}

package sparc.meters;

import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.MethodHook;

import java.lang.invoke.MethodHandle;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Query sinks not covered by Jazzer's built-in SqlInjection detector, which only hooks
 * java.sql.Statement.execute* and javax.persistence.EntityManager.createNativeQuery.
 *
 * Meters:   sql.prepare  - Connection.prepareStatement/prepareCall text; arg = SQL
 *           jpa.query    - EntityManager.createQuery/createNativeQuery (javax and jakarta); arg = query
 *           sql.statement - Connection.createStatement (the built-in detector handles its execute calls)
 * Detects:  SQL injection in prepared-statement text, using the built-in's rule: the driver rejects
 *           the statement as a syntax error AND Jazzer's bundled SQL parser agrees it isn't valid SQL.
 *           The fuzzer is guided toward quote/escape characters, as the built-in does.
 */
public final class SqlHooks {
    private static final String BREAKERS = "'\"\b\n\r\t\\%_";
    private static final Set<String> SYNTAX_ERRORS = new HashSet<>(Arrays.asList(
            "java.sql.SQLSyntaxErrorException", "java.sql.SQLNonTransientException", "java.sql.SQLException",
            "org.h2.jdbc.JdbcSQLSyntaxErrorException", "org.h2.jdbc.JdbcSQLFeatureNotSupportedException",
            "org.postgresql.util.PSQLException"));
    private static final Method PARSE = findParser();

    private SqlHooks() {}

    @MethodHook(type = HookType.REPLACE, targetClassName = "java.sql.Connection", targetMethod = "prepareStatement")
    @MethodHook(type = HookType.REPLACE, targetClassName = "java.sql.Connection", targetMethod = "prepareCall")
    public static Object prepare(MethodHandle original, Object self, Object[] args, int hookId) throws Throwable {
        String sql = args.length > 0 && args[0] instanceof String ? (String) args[0] : null;
        if (sql != null) {
            Meter.reached("sql.prepare", sql, hookId);
            Jazzer.guideTowardsContainment(sql, BREAKERS, hookId);
        }
        Object[] all = new Object[args.length + 1];
        all[0] = self;
        System.arraycopy(args, 0, all, 1, args.length);
        try {
            return original.invokeWithArguments(all);
        } catch (Throwable t) {
            if (sql != null && SYNTAX_ERRORS.contains(t.getClass().getName()) && !isValidSql(sql)) {
                Jazzer.reportFindingFromHook(new FuzzerSecurityIssueHigh(
                        "SQL Injection in prepared statement text\nInjected query: " + sql));
            }
            throw t;
        }
    }

    @MethodHook(type = HookType.BEFORE, targetClassName = "jakarta.persistence.EntityManager", targetMethod = "createNativeQuery")
    @MethodHook(type = HookType.BEFORE, targetClassName = "jakarta.persistence.EntityManager", targetMethod = "createQuery")
    @MethodHook(type = HookType.BEFORE, targetClassName = "javax.persistence.EntityManager", targetMethod = "createQuery")
    public static void jpa(MethodHandle method, Object self, Object[] args, int hookId) {
        if (args.length > 0 && args[0] instanceof String) {  // createQuery(CriteriaQuery) takes no text
            Meter.reached("jpa.query", (String) args[0], hookId);
        }
    }

    @MethodHook(type = HookType.AFTER, targetClassName = "java.sql.Connection", targetMethod = "createStatement")
    public static void statement(MethodHandle method, Object self, Object[] args, int hookId, Object ret) {
        Meter.reached("sql.statement", null, hookId);
    }

    static boolean isValidSql(String sql) {
        if (PARSE == null) return true;  // no parser available: never report
        try {
            PARSE.invoke(null, sql);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static Method findParser() {
        for (String c : new String[] {
                "com.code_intelligence.jazzer.bootstrap.net.sf.jsqlparser.parser.CCJSqlParserUtil",
                "net.sf.jsqlparser.parser.CCJSqlParserUtil"}) {
            try {
                return Class.forName(c).getMethod("parseStatements", String.class);
            } catch (Exception ignored) {
            }
        }
        System.err.println("[meter] no SQL parser found; prepared-statement injection detection disabled");
        return null;
    }
}

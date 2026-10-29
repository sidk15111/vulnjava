package com.sparc.vulnjava.sinks;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.mvel2.MVEL;

/**
 * Sink S4: configurable eligibility rules evaluated with MVEL, the expression engine MOSIP uses for
 * applicant-type and credential rules. Entry -> check the field name -> build expression -> eval.
 *
 *   S4 expression injection: the requested field name is concatenated into the expression text,
 *      so a "field name" can carry arbitrary MVEL (method calls, class access).
 *
 * Passing safe=true checks the field against an allow-list first.
 */
public final class EligibilityRules {
    static final Set<String> FIELDS = Set.of("dateOfBirth", "gender", "residenceStatus", "phone", "email");

    private EligibilityRules() {}

    /** Entry: is the given applicant field present (non-null)? */
    public static boolean hasField(String field, Map<String, Object> applicant, boolean safe) {
        if (field == null || field.isEmpty() || field.length() > 200) {
            throw new IllegalArgumentException("bad field name");
        }
        if (safe && !FIELDS.contains(field)) {
            throw new IllegalArgumentException("unknown field: " + field);
        }
        return evaluate("applicant." + field + " != null", applicant);   // BUG (S4): text concatenation
    }

    static boolean evaluate(String expression, Map<String, Object> applicant) {
        Map<String, Object> vars = new HashMap<>();
        vars.put("applicant", applicant);
        Object result = MVEL.eval(expression, vars);
        return Boolean.TRUE.equals(result);
    }
}

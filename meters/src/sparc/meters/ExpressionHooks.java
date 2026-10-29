package sparc.meters;

import com.code_intelligence.jazzer.api.HookType;
import com.code_intelligence.jazzer.api.Jazzer;
import com.code_intelligence.jazzer.api.MethodHook;
import java.lang.invoke.MethodHandle;

/**
 * Expression engines that Jazzer's built-in EL detector doesn't cover (it only hooks javax/jakarta.el).
 *
 * Meters:   expression.mvel / expression.spel - expression text reached; arg = the expression
 * Detects:  code execution, via Jazzer's honeypot class jaz.Zer: the fuzzer is guided toward an
 *           expression that calls it, and Jazzer reports Remote Code Execution if the engine actually
 *           loads or invokes it. Nothing is reported for expressions that merely look dangerous.
 */
public final class ExpressionHooks {
    static final String MVEL_ATTACK = "jaz.Zer.el()";
    static final String SPEL_ATTACK = "T(jaz.Zer).el()";

    private ExpressionHooks() {}

    @MethodHook(type = HookType.BEFORE, targetClassName = "org.mvel2.MVEL", targetMethod = "eval")
    @MethodHook(type = HookType.BEFORE, targetClassName = "org.mvel2.MVEL", targetMethod = "compileExpression")
    @MethodHook(type = HookType.BEFORE, targetClassName = "org.mvel2.MVEL", targetMethod = "executeExpression")
    @MethodHook(type = HookType.BEFORE, targetClassName = "org.mvel2.templates.TemplateRuntime", targetMethod = "eval")
    public static void mvel(MethodHandle method, Object self, Object[] args, int hookId) {
        if (args.length > 0 && args[0] instanceof String) {
            String expr = (String) args[0];
            Meter.reached("expression.mvel", expr, hookId);
            Jazzer.guideTowardsContainment(expr, MVEL_ATTACK, hookId);
        }
    }

    @MethodHook(type = HookType.BEFORE, targetClassName = "org.springframework.expression.ExpressionParser", targetMethod = "parseExpression")
    @MethodHook(type = HookType.BEFORE, targetClassName = "org.springframework.expression.spel.standard.SpelExpressionParser", targetMethod = "parseExpression")
    @MethodHook(type = HookType.BEFORE, targetClassName = "org.springframework.expression.common.TemplateAwareExpressionParser", targetMethod = "parseExpression")
    public static void spel(MethodHandle method, Object self, Object[] args, int hookId) {
        if (args.length > 0 && args[0] instanceof String) {
            String expr = (String) args[0];
            Meter.reached("expression.spel", expr, hookId);
            Jazzer.guideTowardsContainment(expr, SPEL_ATTACK, hookId);
        }
    }
}

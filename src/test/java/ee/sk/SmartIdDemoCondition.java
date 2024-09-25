package ee.sk;

import java.lang.reflect.AnnotatedElement;
import java.util.Optional;

import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;

public class SmartIdDemoCondition implements ExecutionCondition {

    /**
     * Allows switching off tests going against smart-id demo env.
     * This is sometimes needed if the test data in smart-id is temporarily broken.
     */
    private static final boolean TEST_AGAINST_SMART_ID_DEMO = true;

    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
        Optional<AnnotatedElement> element = context.getElement();
        if (element.isPresent() && element.get().isAnnotationPresent(SmartIdDemoIntegrationTest.class) && !TEST_AGAINST_SMART_ID_DEMO) {
            return ConditionEvaluationResult.disabled("Running against Smart-ID demo is turned off");
        }
        return ConditionEvaluationResult.enabled("Running against Smart-ID demo is turned on");
    }
}

package ee.sk;

import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.InitializationError;

public class SmartIdDemoTestRunner extends BlockJUnit4ClassRunner {

    /**
     * Allows switching off tests going against smart-id demo env.
     * This is sometimes needed if the test data in smart-id is temporarily broken.
     */
    private static final boolean TEST_AGAINST_SMART_ID_DEMO = true;

    public SmartIdDemoTestRunner(Class<?> testClass) throws InitializationError {
        super(testClass);
    }

    @Override
    protected boolean isIgnored(FrameworkMethod method) {
        if (isAnnotationOnClass() && !TEST_AGAINST_SMART_ID_DEMO) {
            return true;
        }
        if (isAnnotationOnMethod(method) && !TEST_AGAINST_SMART_ID_DEMO) {
            return true;
        }
        return super.isIgnored(method);
    }

    private boolean isAnnotationOnClass() {
        return getTestClass().getJavaClass().isAnnotationPresent(SmartIdDemoIntegrationTest.class);
    }

    private static boolean isAnnotationOnMethod(FrameworkMethod method) {
        return method.getAnnotation(SmartIdDemoIntegrationTest.class) != null;
    }
}

package ee.sk;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.api.extension.ExtendWith;

@Target({ElementType.TYPE, ElementType.METHOD}) // Can be applied to classes or methods
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(SmartIdDemoCondition.class)
public @interface SmartIdDemoIntegrationTest {
}

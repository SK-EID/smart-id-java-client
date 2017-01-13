package ee.sk.smartid;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class VerificationCodeCalculatorTest {
    @Test
    public void getVerificationCode() {
        byte[] dummyDocumentHash = new byte[] { 27, -69 };
        String verificationCode = VerificationCodeCalculator.calculate(dummyDocumentHash);
        assertEquals("4555", verificationCode);
    }
}

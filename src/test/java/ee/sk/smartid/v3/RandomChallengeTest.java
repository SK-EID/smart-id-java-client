package ee.sk.smartid.v3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class RandomChallengeTest {

    @Test
    void generate_defaultValueUsed() {
        String challenge = RandomChallenge.generate();

        assertNotNull(challenge);
        byte[] decodeChallenge = Base64.decode(challenge);
        assertEquals(64, decodeChallenge.length);
    }

    @ParameterizedTest
    @ValueSource(ints = {32, 43, 59, 64})
    void generate_providedValuesAreInAllowedRange(int allowedValue) {
        String challenge = RandomChallenge.generate(allowedValue);
        assertNotNull(challenge);
        byte[] decodeChallenge = Base64.decode(challenge);
        assertEquals(allowedValue, decodeChallenge.length);
    }

    @Test
    void generate_providedValueIsLessThanAllowed_throwException() {
        assertThrows(IllegalArgumentException.class, () -> RandomChallenge.generate(31));
    }

    @Test
    void generate_providedValueIsMoreThanAllowed_throwException() {
        assertThrows(IllegalArgumentException.class, () -> RandomChallenge.generate(65));
    }

}
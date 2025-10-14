package ee.sk.smartid;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2025 SK ID Solutions AS
 * %%
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * #L%
 */

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import ee.sk.smartid.exception.permanent.SmartIdClientException;

class FileDefaultTrustedCAStoreBuilderTest {

    @Test
    void validateTrustedCaCertificatesOnInitiation_ocspValidationsDisabled() {
        TrustedCACertStore trustedCACertStore = new FileTrustedCAStoreBuilder().withOcspEnabled(false).build();
        assertFalse(trustedCACertStore.getTrustedCACertificates().isEmpty());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void validateTrustedCaCertificatesOnInitiation_trustStoreAnchorPathIsSetToEmpty_throwException(String path) {
        var ex = assertThrows(SmartIdClientException.class, () -> {
            new FileTrustedCAStoreBuilder()
                    .withOcspEnabled(false)
                    .withTrustAnchorTruststorePath(path)
                    .build();
        });
        assertEquals("Trust anchor truststore path must be set", ex.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void validateTrustedCaCertificatesOnInitiation_trustStoreAnchorPasswordIsSetToEmpty_throwException(String password) {
        var ex = assertThrows(SmartIdClientException.class, () -> {
            new FileTrustedCAStoreBuilder()
                    .withOcspEnabled(false)
                    .withTrustAnchorTruststorePassword(password)
                    .build();
        });
        assertEquals("Trust anchor truststore password must be set", ex.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void validateTrustedCaCertificatesOnInitiation_intermediateCaTruststorePathIsSetToEmpty_throwException(String password) {
        var ex = assertThrows(SmartIdClientException.class, () -> {
            new FileTrustedCAStoreBuilder()
                    .withOcspEnabled(false)
                    .withIntermediateCATruststorePath(password)
                    .build();
        });
        assertEquals("Intermediate CA certificate truststore path must be set", ex.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void validateTrustedCaCertificatesOnInitiation_intermediateCaTruststorePasswordIsSetToEmpty_throwException(String password) {
        var ex = assertThrows(SmartIdClientException.class, () -> {
            new FileTrustedCAStoreBuilder()
                    .withOcspEnabled(false)
                    .withIntermediateCATruststorePassword(password)
                    .build();
        });
        assertEquals("Intermediate CA certificate truststore password must be set", ex.getMessage());
    }

    @Disabled("Not yet implemented")
    @Test
    void validateTrustedCaCertificatesOnInitiation_withOCSPValidationTurnedOn() {
        new FileTrustedCAStoreBuilder()
                .withOcspEnabled(true).build();
    }
}

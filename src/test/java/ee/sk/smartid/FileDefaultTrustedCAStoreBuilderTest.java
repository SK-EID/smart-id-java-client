package ee.sk.smartid;

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
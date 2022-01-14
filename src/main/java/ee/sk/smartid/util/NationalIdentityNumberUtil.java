package ee.sk.smartid.util;

import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;

public class NationalIdentityNumberUtil {
    private static final Logger logger = LoggerFactory.getLogger(NationalIdentityNumberUtil.class);

    private static final DateTimeFormatter DATE_FORMATTER_YYYY_MM_DD = DateTimeFormatter.ofPattern("uuuuMMdd")
            .withResolverStyle(ResolverStyle.STRICT);

    /**
     * Detect date-of-birth from a Baltic national identification number if possible or return null.
     *
     * This method always returns the value for all Estonian and Lithuanian national identification numbers.
     *
     * It also works for older Latvian personal codes but Latvian personal codes issued after July 1st 2017
     * (starting with "32") do not carry date-of-birth.
     *
     * For non-Baltic countries (countries other than Estonia, Latvia or Lithuania) it always returns null
     * (even if it would be possible to deduce date of birth from national identity number).
     *
     * Newer (but not all) Smart-ID certificates have date-of-birth on a separate attribute.
     * It is recommended to use that value if present.
     * @see CertificateAttributeUtil#getDateOfBirth(java.security.cert.X509Certificate)
     *
     * @param authenticationIdentity Authentication identity
     * @return DateOfBirth or null if it cannot be detected from personal code
     */
    public static LocalDate getDateOfBirth(AuthenticationIdentity authenticationIdentity) {
        String identityNumber = authenticationIdentity.getIdentityNumber();

        switch ( authenticationIdentity.getCountry().toUpperCase()) {
            case "EE":
            case "LT":
                return parseEeLtDateOfBirth(identityNumber);
            case "LV":
                return parseLvDateOfBirth(identityNumber);
            default:
                return null;
        }
    }

    public static LocalDate parseEeLtDateOfBirth(String eeOrLtNationalIdentityNumber) {
        String birthDate = eeOrLtNationalIdentityNumber.substring(1, 7);

        switch (eeOrLtNationalIdentityNumber.substring(0, 1)) {
            case "1":
            case "2":
                birthDate = "18" + birthDate;
                break;
            case "3":
            case "4":
                birthDate = "19" + birthDate;
                break;
            case "5":
            case "6":
                birthDate = "20" + birthDate;
                break;
            default:
                throw new RuntimeException("Invalid personal code " + eeOrLtNationalIdentityNumber);
        }

        try {
            return LocalDate.parse(birthDate, DATE_FORMATTER_YYYY_MM_DD);
        } catch (DateTimeParseException e) {
            throw new UnprocessableSmartIdResponseException("Could not parse birthdate from nationalIdentityNumber=" + eeOrLtNationalIdentityNumber, e);
        }
    }

    public static LocalDate parseLvDateOfBirth(String lvNationalIdentityNumber) {
        String birthDay = lvNationalIdentityNumber.substring(0, 2);
        if ("32".equals(birthDay)) {
            logger.debug("Person has newer type of Latvian ID-code that does not carry birthdate info");
            return null;
        }

        String birthMonth = lvNationalIdentityNumber.substring(2, 4);
        String birthYearTwoDigit = lvNationalIdentityNumber.substring(4, 6);
        String century = lvNationalIdentityNumber.substring(7, 8);
        String birthDateYyyyMmDd;

        switch (century) {
            case "0":
                birthDateYyyyMmDd = "18" + (birthYearTwoDigit + birthMonth + birthDay);
                break;
            case "1":
                birthDateYyyyMmDd = "19" + (birthYearTwoDigit + birthMonth + birthDay);
                break;
            case "2":
                birthDateYyyyMmDd = "20" + (birthYearTwoDigit + birthMonth + birthDay);
                break;
            default:
                throw new UnprocessableSmartIdResponseException("Invalid personal code: " + lvNationalIdentityNumber);
        }

        try {
            return LocalDate.parse(birthDateYyyyMmDd, DATE_FORMATTER_YYYY_MM_DD);
        } catch (DateTimeParseException e) {
            throw new UnprocessableSmartIdResponseException("Unable get birthdate from Latvian personal code " + lvNationalIdentityNumber, e);
        }
    }

}

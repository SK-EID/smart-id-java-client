package ee.sk.smartid.util;

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

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;

/**
 * Utility class for handling national identity numbers (personal codes).
 */
public class NationalIdentityNumberUtil {

    private static final Logger logger = LoggerFactory.getLogger(NationalIdentityNumberUtil.class);

    private static final DateTimeFormatter DATE_FORMATTER_YYYY_MM_DD = DateTimeFormatter.ofPattern("uuuuMMdd")
            .withResolverStyle(ResolverStyle.STRICT);

    /**
     * Detect date-of-birth from a Baltic national identification number if possible or return null.
     * <p>
     * This method always returns the value for all Estonian and Lithuanian national identification numbers.
     * <p>
     * It also works for older Latvian personal codes but Latvian personal codes issued after July 1st 2017
     * (starting with "32") do not carry date-of-birth.
     * <p>
     * For non-Baltic countries (countries other than Estonia, Latvia or Lithuania) it always returns null
     * (even if it would be possible to deduce date of birth from national identity number).
     * <p>
     * Newer (but not all) Smart-ID certificates have date-of-birth on a separate attribute.
     * It is recommended to use that value if present.
     *
     * @param authenticationIdentity Authentication identity
     * @return DateOfBirth or null if it cannot be detected from personal code
     * @see CertificateAttributeUtil#getDateOfBirth(java.security.cert.X509Certificate)
     */
    public static LocalDate getDateOfBirth(AuthenticationIdentity authenticationIdentity) {
        String identityNumber = authenticationIdentity.getIdentityNumber();

        return switch (authenticationIdentity.getCountry().toUpperCase()) {
            case "EE", "LT" -> parseEeLtDateOfBirth(identityNumber);
            case "LV" -> parseLvDateOfBirth(identityNumber);
            default -> null;
        };
    }

    /**
     * Parses date of birth from Estonian or Lithuanian national identity number.
     *
     * @param eeOrLtNationalIdentityNumber Estonian or Lithuanian national identity number
     * @return Date of birth
     * @throws UnprocessableSmartIdResponseException if the national identity number is invalid or date cannot be parsed
     */
    public static LocalDate parseEeLtDateOfBirth(String eeOrLtNationalIdentityNumber) {
        String birthDate = eeOrLtNationalIdentityNumber.substring(1, 7);

        birthDate = switch (eeOrLtNationalIdentityNumber.substring(0, 1)) {
            case "1", "2" -> "18" + birthDate;
            case "3", "4" -> "19" + birthDate;
            case "5", "6" -> "20" + birthDate;
            default -> throw new RuntimeException("Invalid personal code " + eeOrLtNationalIdentityNumber);
        };

        try {
            return LocalDate.parse(birthDate, DATE_FORMATTER_YYYY_MM_DD);
        } catch (DateTimeParseException e) {
            throw new UnprocessableSmartIdResponseException("Could not parse birthdate from nationalIdentityNumber=" + eeOrLtNationalIdentityNumber, e);
        }
    }

    /**
     * Parses date of birth from Latvian national identity number if possible.
     * <p>
     * Latvian personal codes issued after July 1st 2017 (starting with "32") do not carry date-of-birth and null is returned.
     *
     * @param lvNationalIdentityNumber Latvian national identity number
     * @return Date of birth or null if the personal code does not carry birthdate info
     * @throws UnprocessableSmartIdResponseException if the national identity number is invalid or date cannot be parsed
     */
    public static LocalDate parseLvDateOfBirth(String lvNationalIdentityNumber) {
        String birthDay = lvNationalIdentityNumber.substring(0, 2);
        if (isNonParsableLVPersonCodePrefix(birthDay)) {
            logger.debug("Person has newer type of Latvian ID-code that does not carry birthdate info");
            return null;
        }

        String birthMonth = lvNationalIdentityNumber.substring(2, 4);
        String birthYearTwoDigit = lvNationalIdentityNumber.substring(4, 6);
        String century = lvNationalIdentityNumber.substring(7, 8);
        String birthDateYyyyMmDd = switch (century) {
            case "0" -> "18" + (birthYearTwoDigit + birthMonth + birthDay);
            case "1" -> "19" + (birthYearTwoDigit + birthMonth + birthDay);
            case "2" -> "20" + (birthYearTwoDigit + birthMonth + birthDay);
            default -> throw new UnprocessableSmartIdResponseException("Invalid personal code: " + lvNationalIdentityNumber);
        };

        try {
            return LocalDate.parse(birthDateYyyyMmDd, DATE_FORMATTER_YYYY_MM_DD);
        } catch (DateTimeParseException e) {
            throw new UnprocessableSmartIdResponseException("Unable get birthdate from Latvian personal code " + lvNationalIdentityNumber, e);
        }
    }

    private static boolean isNonParsableLVPersonCodePrefix(String prefix) {
        Pattern pattern = Pattern.compile("3[2-9]");
        Matcher matcher = pattern.matcher(prefix);
        return matcher.matches();
    }
}

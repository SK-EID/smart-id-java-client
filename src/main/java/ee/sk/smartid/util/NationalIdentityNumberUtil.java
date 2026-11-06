package ee.sk.smartid.util;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2026 SK ID Solutions AS
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

    private static final Pattern BE_PERSON_CODE_PATTERN = Pattern.compile("[0-9]{11}");
    private static final String BE_UNKNOWN_BIRTH_DAY = "00";
    private static final int BE_UNKNOWN_BIRTH_MONTH = 0;
    private static final int BE_CHECK_DIGIT_MODULUS = 97;
    private static final long BE_BORN_IN_21ST_CENTURY_PREFIX = 2_000_000_000L;
    private static final int BE_BIS_NUMBER_MONTH_OFFSET_KNOWN_GENDER = 20;
    private static final int BE_BIS_NUMBER_MONTH_OFFSET_UNKNOWN_GENDER = 40;

    /**
     * Detect date-of-birth from a national identification number if possible or return null.
     * <p>
     * This method always returns the value for all Estonian and Lithuanian national identification numbers.
     * <p>
     * It also works for older Latvian personal codes but Latvian personal codes issued after July 1st 2017
     * (starting with "32") do not carry date-of-birth.
     * <p>
     * Belgian national register numbers carry date-of-birth unless the birth month and day are unknown (both are zeroes).
     * <p>
     * For other countries (countries other than Estonia, Latvia, Lithuania or Belgium) it always returns null
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
            case "BE" -> parseBeDateOfBirth(identityNumber);
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

    /**
     * Parses date of birth from Belgian national register number if possible.
     * <p>
     * The number consists of 11 digits in the form YYMMDDXXXCD, where YYMMDD is the date of birth, XXX the daily
     * serial number and CD the check digit. As the birth year is given with two digits only, the century is deduced
     * from the check digit, see {@link #determineBeBirthCentury(String)}.
     * <p>
     * A bisnummer, issued to persons not registered in the National Registry, carries the birth month increased
     * by 20 if the person's gender is known and by 40 if it is not. The offset is removed before the date is parsed,
     * but the check digit is always calculated over the number as issued.
     * <p>
     * If birth month and day are not known (both are zeroes) then null is returned.
     *
     * @param beNationalIdentityNumber Belgian national register number
     * @return Date of birth or null if the personal code does not carry birthdate info
     * @throws UnprocessableSmartIdResponseException if the national identity number is invalid or date cannot be parsed
     */
    public static LocalDate parseBeDateOfBirth(String beNationalIdentityNumber) {
        if (beNationalIdentityNumber == null || !BE_PERSON_CODE_PATTERN.matcher(beNationalIdentityNumber).matches()) {
            throw new UnprocessableSmartIdResponseException("Invalid personal code: " + beNationalIdentityNumber);
        }

        String birthCentury = determineBeBirthCentury(beNationalIdentityNumber);

        String birthYearTwoDigit = beNationalIdentityNumber.substring(0, 2);
        int birthMonth = removeBeBisNumberMonthOffset(Integer.parseInt(beNationalIdentityNumber.substring(2, 4)));
        String birthDay = beNationalIdentityNumber.substring(4, 6);

        if (birthMonth == BE_UNKNOWN_BIRTH_MONTH && BE_UNKNOWN_BIRTH_DAY.equals(birthDay)) {
            logger.debug("Person has a Belgian national register number that does not carry birthdate info");
            return null;
        }

        String birthDateYyyyMmDd = birthCentury + birthYearTwoDigit + "%02d".formatted(birthMonth) + birthDay;
        try {
            return LocalDate.parse(birthDateYyyyMmDd, DATE_FORMATTER_YYYY_MM_DD);
        } catch (DateTimeParseException e) {
            throw new UnprocessableSmartIdResponseException("Unable to get birthdate from Belgian personal code " + beNationalIdentityNumber, e);
        }
    }

    /**
     * Removes the bisnummer offset from the birth month given in a Belgian national register number.
     * <p>
     * The month of a bisnummer is increased by 20 if the person's gender is known and by 40 if it is not.
     * The month of a regular national register number is returned as is.
     *
     * @param birthMonthFromPersonalCode birth month as given in the national register number
     * @return birth month without the bisnummer offset
     */
    private static int removeBeBisNumberMonthOffset(int birthMonthFromPersonalCode) {
        if (birthMonthFromPersonalCode >= BE_BIS_NUMBER_MONTH_OFFSET_UNKNOWN_GENDER) {
            return birthMonthFromPersonalCode - BE_BIS_NUMBER_MONTH_OFFSET_UNKNOWN_GENDER;
        }
        if (birthMonthFromPersonalCode >= BE_BIS_NUMBER_MONTH_OFFSET_KNOWN_GENDER) {
            return birthMonthFromPersonalCode - BE_BIS_NUMBER_MONTH_OFFSET_KNOWN_GENDER;
        }
        return birthMonthFromPersonalCode;
    }

    /**
     * Determines the century of birth from the check digit of a Belgian national register number.
     * <p>
     * The check digit is calculated over the first 9 digits (YYMMDDXXX) of the number. If it matches the check digit
     * in the number then the person was born in the 20th century. If it does not, the calculation is repeated over
     * the same 9 digits prefixed with "2"; a match then means the person was born in the 21st century. If neither
     * calculation matches, the number is not a valid Belgian national register number.
     *
     * @param beNationalIdentityNumber Belgian national register number
     * @return "19" or "20"
     * @throws UnprocessableSmartIdResponseException if the check digit matches neither century
     */
    private static String determineBeBirthCentury(String beNationalIdentityNumber) {
        long codeWithoutCheckDigit = Long.parseLong(beNationalIdentityNumber.substring(0, 9));
        int checkDigit = Integer.parseInt(beNationalIdentityNumber.substring(9));

        if (checkDigit == calculateBeCheckDigit(codeWithoutCheckDigit)) {
            return "19";
        }
        if (checkDigit == calculateBeCheckDigit(BE_BORN_IN_21ST_CENTURY_PREFIX + codeWithoutCheckDigit)) {
            return "20";
        }
        throw new UnprocessableSmartIdResponseException("Invalid personal code: " + beNationalIdentityNumber);
    }

    private static int calculateBeCheckDigit(long codeWithoutCheckDigit) {
        return (int) (BE_CHECK_DIGIT_MODULUS - codeWithoutCheckDigit % BE_CHECK_DIGIT_MODULUS);
    }

    private static boolean isNonParsableLVPersonCodePrefix(String prefix) {
        Pattern pattern = Pattern.compile("3[2-9]");
        Matcher matcher = pattern.matcher(prefix);
        return matcher.matches();
    }
}

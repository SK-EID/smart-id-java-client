package ee.sk.smartid.rest.dao;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 SK ID Solutions AS
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

import java.io.Serializable;

/**
 * Representation of Semantic Identifier.
 */
public class SemanticsIdentifier implements Serializable {

    private final String identifier;

    /**
     * Constructs a new SemanticsIdentifier with the specified identity type, country code and identity number.
     *
     * @param identityType   the identity type (e.g., PAS, IDC, PNO). See {@link IdentityType}
     * @param countryCode    the country code (e.g., EE, LT, LV). See {@link CountryCode}
     * @param identityNumber the identity number
     */
    public SemanticsIdentifier(IdentityType identityType, CountryCode countryCode, String identityNumber) {
        this.identifier = "" + identityType + countryCode + "-" + identityNumber;
    }

    /**
     * Constructs a new SemanticsIdentifier with the specified identity type, country code string and identity number.
     *
     * @param identityType      the identity type (e.g., PAS, IDC, PNO). See {@link IdentityType}
     * @param countryCodeString country code as string (e.g., EE, LT, LV)
     * @param identityNumber    the identity number
     */
    public SemanticsIdentifier(IdentityType identityType, String countryCodeString, String identityNumber) {
        this.identifier = "" + identityType + countryCodeString + "-" + identityNumber;
    }

    /**
     * Constructs a new SemanticsIdentifier with the specified identity type string, country code string and identity number.
     *
     * @param identityTypeString the identity type as string (e.g., PAS, IDC, PNO)
     * @param countryCodeString  country code as string (e.g., EE, LT, LV)
     * @param identityNumber     the identity number
     */
    public SemanticsIdentifier(String identityTypeString, String countryCodeString, String identityNumber) {
        this.identifier = "" + identityTypeString + countryCodeString + "-" + identityNumber;
    }

    /**
     * Constructs a new SemanticsIdentifier with the specified identifier string.
     *
     * @param identifier the full semantics identifier string (e.g., "PAS EE-1234567890")
     */
    public SemanticsIdentifier(String identifier) {
        this.identifier = identifier;
    }

    /**
     * Gets the full semantics identifier string.
     *
     * @return the full semantics identifier string
     */
    public String getIdentifier() {
        return identifier;
    }

    /**
     * 3-character identity type codes for SemanticsIdentifier
     */
    public enum IdentityType {

        /**
         * PAS - Passport
         */
        PAS,

        /**
         * IDC - Identity Card
         */
        IDC,

        /**
         * PNO - Personal Number
         */
        PNO
    }

    /**
     * 2-character country codes for SemanticsIdentifier
     */
    public enum CountryCode {

        /**
         * Estonia
         */
        EE,

        /**
         * Lithuania
         */
        LT,

        /**
         * Latvia
         */
        LV
    }

    @Override
    public String toString() {
        return "SemanticsIdentifier{" +
                "identifier='" + identifier + '\'' +
                '}';
    }

}

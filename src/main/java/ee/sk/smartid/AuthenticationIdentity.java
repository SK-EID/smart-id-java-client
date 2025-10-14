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

import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.Optional;

/**
 * Represents users identity in the validated authentication certificate
 */
public class AuthenticationIdentity {

    private String givenName;
    private String surname;
    private String identityNumber;
    private String country;
    private X509Certificate authCertificate;
    private LocalDate dateOfBirth;

    /**
     * Initializes a new instance of the authentication identity.
     */
    public AuthenticationIdentity() {
    }

    /**
     * Initializes a new instance of authentication identity with the authentication certificate.
     *
     * @param authCertificate the authentication certificate where the identity information is extracted from
     */
    public AuthenticationIdentity(X509Certificate authCertificate) {
        this.authCertificate = authCertificate;
    }

    /**
     * Gets the given name of the user.
     *
     * @return the given name of the user
     */
    public String getGivenName() {
        return givenName;
    }

    /**
     * Sets the given name of the user.
     *
     * @param givenName the given name of the user
     */
    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    /**
     * Gets the surname of the user.
     *
     * @return the surname of the user
     */
    public String getSurname() {
        return surname;
    }

    /**
     * Sets the surname of the user.
     *
     * @param surname the surname of the user
     */
    public void setSurname(String surname) {
        this.surname = surname;
    }

    /**
     * Gets the identity number of the user.
     *
     * @return the identity number of the user
     */
    public String getIdentityNumber() {
        return identityNumber;
    }

    /**
     * Sets the identity number of the user.
     * <p>
     * The identity number is also known as national identification number, personal code, social security number etc.
     * <p>
     * Should be used if the value are only the numbers. F.e. 12345678901
     *
     * @param identityNumber the identity number of the user
     */
    public void setIdentityNumber(String identityNumber) {
        this.identityNumber = identityNumber;
    }

    /**
     * Gets the identity number of the user.
     *
     * @return the identity code of the user
     */
    public String getIdentityCode() {
        return identityNumber;
    }

    /**
     * Sets the identity number of the user.
     * <p>
     * The identity number is also known as national identification number, personal code, social security number etc.
     * <p>
     * Should be used if the value contains alphanumeric characters. F.e. EE12345678901, 1234567-8901
     *
     * @param identityCode the identity code of the user
     */
    public void setIdentityCode(String identityCode) {
        this.identityNumber = identityCode;
    }

    /**
     * Gets the country code of the user.
     *
     * @return the country code of the user
     */
    public String getCountry() {
        return country;
    }

    /**
     * Sets the country code of the user.
     *
     * @param country the country code of the user
     */
    public void setCountry(String country) {
        this.country = country;
    }

    /**
     * Gets the authentication certificate of the user.
     *
     * @return the authentication certificate of the user
     */
    public X509Certificate getAuthCertificate() {
        return authCertificate;
    }

    /**
     * Person's date of birth.
     *
     * @return Date of birth if this information is available in authentication response or empty optional.
     */
    public Optional<LocalDate> getDateOfBirth() {
        return Optional.ofNullable(dateOfBirth);
    }

    /**
     * Sets person's date of birth.
     *
     * @param dateOfBirth Date of birth
     */
    public void setDateOfBirth(LocalDate dateOfBirth) {
        this.dateOfBirth = dateOfBirth;
    }

}

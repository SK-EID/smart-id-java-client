package ee.sk.smartid.dao;

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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

import ee.sk.smartid.rest.dao.SemanticsIdentifier;

class SemanticsIdentifierTest {

    private static final String IDENTITY_NUMBER = "30303039914";

    @Test
    void getIdentifier_createdFromIdentityTypeCountryCodeAndIdentityNumberStrings() {
        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNO", "EE", IDENTITY_NUMBER);

        assertThat(semanticsIdentifier.getIdentifier(), is("PNOEE-" + IDENTITY_NUMBER));
    }

    @Test
    void getIdentifier_createdFromFullIdentifierString() {
        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("PNOEE-" + IDENTITY_NUMBER);

        assertThat(semanticsIdentifier.getIdentifier(), is("PNOEE-" + IDENTITY_NUMBER));
    }

    @ParameterizedTest
    @EnumSource(SemanticsIdentifier.IdentityType.class)
    void getIdentifier_createdWithIdentityTypeAndCountryCodeString(SemanticsIdentifier.IdentityType identityType) {
        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(identityType, "EE", IDENTITY_NUMBER);

        assertThat(semanticsIdentifier.getIdentifier(), is(identityType + "EE-" + IDENTITY_NUMBER));
    }

    @ParameterizedTest
    @EnumSource(SemanticsIdentifier.CountryCode.class)
    void getIdentifier_createdWithIdentityTypeAndCountryCode(SemanticsIdentifier.CountryCode countryCode) {
        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, countryCode, IDENTITY_NUMBER);

        assertThat(semanticsIdentifier.getIdentifier(), is("PNO" + countryCode + "-" + IDENTITY_NUMBER));
    }

    @ParameterizedTest
    @CsvSource({
            "EE, 30303039914, PNOEE-30303039914",
            "LT, 30303039914, PNOLT-30303039914",
            "LV, 030303-10012, PNOLV-030303-10012",
            "BE, 93051822361, PNOBE-93051822361"
    })
    void getIdentifier_countrySpecificIdentityNumberIsKeptAsIs(SemanticsIdentifier.CountryCode countryCode,
                                                               String identityNumber,
                                                               String expectedIdentifier) {
        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, countryCode, identityNumber);

        assertThat(semanticsIdentifier.getIdentifier(), is(expectedIdentifier));
    }
}

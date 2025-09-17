package ee.sk.smartid;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2024 SK ID Solutions AS
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
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.rest.dao.SessionResult;
import ee.sk.smartid.rest.dao.SessionResultDetails;
import ee.sk.smartid.rest.dao.SessionStatus;

class ErrorResultHandlerTest {

    @Test
    void handle_nullInput() {
        var smartIdClientException = assertThrows(SmartIdClientException.class, () -> ErrorResultHandler.handle(null));
        assertEquals("Parameter 'sessionResult' is not provided", smartIdClientException.getMessage());
    }

    @ParameterizedTest
    @ArgumentsSource(SessionEndResultErrorArgumentsProvider.class)
    void handle_notOKEndResults(String endResult, Class<? extends SmartIdClientException> expectedException) {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult(endResult);

        assertThrows(expectedException, () -> ErrorResultHandler.handle(sessionResult));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "UNKNOWN"})
    void handle_unknownEndResult(String unknownEndResult) {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult(unknownEndResult);

        var smartIdClientException = assertThrows(SmartIdClientException.class, () -> ErrorResultHandler.handle(sessionResult));
        assertEquals("Unexpected session result: " + unknownEndResult, smartIdClientException.getMessage());
    }

    @Test
    void handle_endResultIsUserRefusedInteraction_detailsMissing() {
        var sessionResult = new SessionResult();
        sessionResult.setEndResult("USER_REFUSED_INTERACTION");

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> ErrorResultHandler.handle(sessionStatus.getResult()));
        assertEquals("Details for refused interaction are missing", exception.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void from_endResultIsUserRefusedInteraction_interactionIsEmpty(String interaction) {
        var sessionResultDetails = new SessionResultDetails();
        sessionResultDetails.setInteraction(interaction);

        var sessionResult = new SessionResult();
        sessionResult.setEndResult("USER_REFUSED_INTERACTION");
        sessionResult.setDetails(sessionResultDetails);

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> ErrorResultHandler.handle(sessionStatus.getResult()));
        assertEquals("Details for refused interaction are missing", exception.getMessage());
    }

    @Test
    void handle_endResultIsUserRefusedInteraction_interactionIsInvalidValue() {
        var sessionResultDetails = new SessionResultDetails();
        sessionResultDetails.setInteraction("invalid interaction");

        var sessionResult = new SessionResult();
        sessionResult.setEndResult("USER_REFUSED_INTERACTION");
        sessionResult.setDetails(sessionResultDetails);

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);

        var exception = assertThrows(UnprocessableSmartIdResponseException.class, () -> ErrorResultHandler.handle(sessionStatus.getResult()));
        assertEquals("Unexpected interaction type: invalid interaction", exception.getMessage());
    }

    @ParameterizedTest
    @ArgumentsSource(UserRefusedInteractionArgumentsProvider.class)
    void handle_endResultIsUserRefusedInteraction(String interaction, Class<? extends Exception> expectedException) {
        var sessionResultDetails = new SessionResultDetails();
        sessionResultDetails.setInteraction(interaction);

        var sessionResult = new SessionResult();
        sessionResult.setEndResult("USER_REFUSED_INTERACTION");
        sessionResult.setDetails(sessionResultDetails);

        var sessionStatus = new SessionStatus();
        sessionStatus.setResult(sessionResult);

        assertThrows(expectedException, () -> ErrorResultHandler.handle(sessionStatus.getResult()));
    }
}

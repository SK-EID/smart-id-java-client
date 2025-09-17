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

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.UserAccountException;
import ee.sk.smartid.exception.UserActionException;
import ee.sk.smartid.exception.permanent.ExpectedLinkedSessionException;
import ee.sk.smartid.exception.permanent.ProtocolFailureException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.permanent.SmartIdServerException;
import ee.sk.smartid.exception.useraccount.DocumentUnusableException;
import ee.sk.smartid.exception.useraccount.RequiredInteractionNotSupportedByAppException;
import ee.sk.smartid.exception.useraction.SessionTimeoutException;
import ee.sk.smartid.exception.useraction.UserRefusedCertChoiceException;
import ee.sk.smartid.exception.useraction.UserRefusedConfirmationMessageException;
import ee.sk.smartid.exception.useraction.UserRefusedConfirmationMessageWithVerificationChoiceException;
import ee.sk.smartid.exception.useraction.UserRefusedDisplayTextAndPinException;
import ee.sk.smartid.exception.useraction.UserRefusedException;
import ee.sk.smartid.exception.useraction.UserSelectedWrongVerificationCodeException;
import ee.sk.smartid.rest.dao.SessionResult;
import ee.sk.smartid.util.StringUtil;

/**
 * Handles session status results that end as completed but with an error
 */
public class ErrorResultHandler {

    /**
     * Handles the session result and throws an appropriate exception
     *
     * @param sessionResult the session result to handle
     * @throws UserActionException
     * @throws UserAccountException
     * @throws UnprocessableSmartIdResponseException
     */
    public static void handle(SessionResult sessionResult) {
        if (sessionResult == null) {
            throw new SmartIdClientException("Session end result is not provided");
        }
        switch (sessionResult.getEndResult()) {
            case "USER_REFUSED" -> throw new UserRefusedException();
            case "TIMEOUT" -> throw new SessionTimeoutException();
            case "DOCUMENT_UNUSABLE" -> throw new DocumentUnusableException();
            case "WRONG_VC" -> throw new UserSelectedWrongVerificationCodeException();
            case "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP" -> throw new RequiredInteractionNotSupportedByAppException();
            case "USER_REFUSED_CERT_CHOICE" -> throw new UserRefusedCertChoiceException();
            case "USER_REFUSED_INTERACTION" -> handleUserRefusedInteraction(sessionResult);
            case "PROTOCOL_FAILURE" -> throw new ProtocolFailureException();
            case "EXPECTED_LINKED_SESSION" -> throw new ExpectedLinkedSessionException();
            case "SERVER_ERROR" -> throw new SmartIdServerException();
            default -> throw new UnprocessableSmartIdResponseException("Unexpected session result: " + sessionResult.getEndResult());
        }
    }

    private static void handleUserRefusedInteraction(SessionResult sessionResult) {
        if (sessionResult.getDetails() == null || StringUtil.isEmpty(sessionResult.getDetails().getInteraction())) {
            throw new UnprocessableSmartIdResponseException("Details for refused interaction are missing");
        }
        switch (sessionResult.getDetails().getInteraction()) {
            case "displayTextAndPIN" -> throw new UserRefusedDisplayTextAndPinException();
            case "confirmationMessage" -> throw new UserRefusedConfirmationMessageException();
            case "confirmationMessageAndVerificationCodeChoice" -> throw new UserRefusedConfirmationMessageWithVerificationChoiceException();
            default -> throw new UnprocessableSmartIdResponseException("Unexpected interaction type: " + sessionResult.getDetails().getInteraction());
        }
    }
}

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

import ee.sk.smartid.exception.UnprocessableSmartIdResponseException;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.exception.useraccount.DocumentUnusableException;
import ee.sk.smartid.exception.useraccount.RequiredInteractionNotSupportedByAppException;
import ee.sk.smartid.exception.useraction.SessionTimeoutException;
import ee.sk.smartid.exception.useraction.UserRefusedCertChoiceException;
import ee.sk.smartid.exception.useraction.UserRefusedConfirmationMessageException;
import ee.sk.smartid.exception.useraction.UserRefusedConfirmationMessageWithVerificationChoiceException;
import ee.sk.smartid.exception.useraction.UserRefusedDisplayTextAndPinException;
import ee.sk.smartid.exception.useraction.UserRefusedException;
import ee.sk.smartid.exception.useraction.UserRefusedVerificationChoiceException;
import ee.sk.smartid.exception.useraction.UserSelectedWrongVerificationCodeException;

/**
 * Handles session status results that end as completed but with an error
 */
public class ErrorResultHandler {

    public static void handle(String endResult) {
        if (endResult == null) {
            throw new SmartIdClientException("Session end result is not provided");
        }

        switch (endResult.toUpperCase()) {
            case "USER_REFUSED" -> throw new UserRefusedException();
            case "TIMEOUT" -> throw new SessionTimeoutException();
            case "DOCUMENT_UNUSABLE" -> throw new DocumentUnusableException();
            case "WRONG_VC" -> throw new UserSelectedWrongVerificationCodeException();
            case "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP" -> throw new RequiredInteractionNotSupportedByAppException();
            case "USER_REFUSED_CERT_CHOICE" -> throw new UserRefusedCertChoiceException();
            case "USER_REFUSED_DISPLAYTEXTANDPIN" -> throw new UserRefusedDisplayTextAndPinException();
            case "USER_REFUSED_VC_CHOICE" -> throw new UserRefusedVerificationChoiceException();
            case "USER_REFUSED_CONFIRMATIONMESSAGE" -> throw new UserRefusedConfirmationMessageException();
            case "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE" -> throw new UserRefusedConfirmationMessageWithVerificationChoiceException();
            default -> throw new UnprocessableSmartIdResponseException("Unexpected session result: " + endResult);
        }
    }
}

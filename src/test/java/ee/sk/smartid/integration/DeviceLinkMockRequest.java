package ee.sk.smartid.integration;

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

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Object to send to Smart-ID Mock service to simulate user-action in the Device Link flow.
 *
 * @param documentNumber     Required. The document number of the user.
 * @param deviceLink         Required. The device link URL generated for device link flow
 * @param flowType           Required. Supported values QR, Web2App and App2App
 * @param browserCookie      Required for Web2App and App2App flows. The browser cookie value for the session.
 * @param initialCallbackUrl Required for Web2App and App2App flows. The initial callback URL to which the user will be redirected.
 */
public record DeviceLinkMockRequest(String documentNumber,
                                    String deviceLink,
                                    String flowType,
                                    @JsonInclude(JsonInclude.Include.NON_EMPTY) String browserCookie,
                                    @JsonInclude(JsonInclude.Include.NON_EMPTY) String initialCallbackUrl) {
}

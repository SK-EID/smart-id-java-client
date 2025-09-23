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

import java.nio.charset.StandardCharsets;

import ee.sk.smartid.auth.AuthenticationCertificatePurposeValidatorFactory;
import ee.sk.smartid.auth.AuthenticationCertificatePurposeValidatorFactoryImpl;
import ee.sk.smartid.rest.dao.NotificationAuthenticationSessionRequest;
import ee.sk.smartid.util.StringUtil;

/**
 * Validates notification-based authentication session status
 */
public class NotificationAuthenticationResponseValidator extends AuthenticationResponseValidator<NotificationAuthenticationSessionRequest> {

    /**
     * Creates an instance of {@link NotificationAuthenticationResponseValidator}
     * using {@link CertificateValidator}, {@link AuthenticationResponseMapper} and {@link SignatureValueValidator}
     *
     * @param certificateValidator         validator used to verify the authentication certificate is valid and trusted
     * @param authenticationResponseMapper the mapper to convert session status to authentication response
     * @param signatureValueValidator      validator used to verify the correctness of the authentication signature value
     */
    public NotificationAuthenticationResponseValidator(CertificateValidator certificateValidator,
                                                       AuthenticationResponseMapper authenticationResponseMapper,
                                                       SignatureValueValidator signatureValueValidator, AuthenticationCertificatePurposeValidatorFactory authenticationCertificatePurposeValidatorFactory) {
        super(certificateValidator, authenticationResponseMapper, authenticationCertificatePurposeValidatorFactory, signatureValueValidator);
    }

    /**
     * Creates an instance of {@link NotificationAuthenticationResponseValidator} using {@link CertificateValidator}
     * and using default implementations of {@link AuthenticationResponseMapperImpl} and {@link SignatureValueValidatorImpl}
     *
     * @param certificateValidator validator used to verify the authentication certificate is valid and trusted
     * @return a new instance of {@link NotificationAuthenticationResponseValidator}
     */
    public static NotificationAuthenticationResponseValidator defaultSetupWithCertificateValidator(CertificateValidator certificateValidator) {
        return new NotificationAuthenticationResponseValidator(certificateValidator,
                new AuthenticationResponseMapperImpl(),
                new SignatureValueValidatorImpl(),
                new AuthenticationCertificatePurposeValidatorFactoryImpl());
    }

    @Override
    protected AuthenticationCertificateLevel getRequestedCertificateLevel(NotificationAuthenticationSessionRequest authenticationSessionRequest) {
        return authenticationSessionRequest.certificateLevel() == null
                ? AuthenticationCertificateLevel.QUALIFIED
                : AuthenticationCertificateLevel.valueOf(authenticationSessionRequest.certificateLevel());
    }

    @Override
    protected byte[] constructPayload(AuthenticationResponse authenticationResponse,
                                      NotificationAuthenticationSessionRequest authenticationSessionRequest,
                                      String schemaName,
                                      String brokeredRpName) {
        String[] payload = {
                schemaName,
                SignatureProtocol.ACSP_V2.name(),
                authenticationResponse.getServerRandom(),
                authenticationSessionRequest.signatureProtocolParameters().rpChallenge(),
                StringUtil.orEmpty(authenticationResponse.getUserChallenge()),
                toBase64(authenticationSessionRequest.relyingPartyName()),
                StringUtil.isEmpty(brokeredRpName) ? "" : toBase64(brokeredRpName),
                toInteractionsBase64(authenticationSessionRequest.interactions()),
                authenticationResponse.getInteractionTypeUsed(),
                "",
                authenticationResponse.getFlowType().getDescription()
        };
        return String
                .join("|", payload)
                .getBytes(StandardCharsets.UTF_8);
    }
}
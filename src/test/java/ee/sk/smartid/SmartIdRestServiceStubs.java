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

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;

public class SmartIdRestServiceStubs {

    public static void stubNotFoundResponse(String urlEquals) {
        stubFor(get(urlEqualTo(urlEquals))
                .withHeader("Accept", equalTo("application/json"))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withHeader("Content-Type", "application/json")
                        .withBody("Not found")));
    }

    public static void stubPostRequestWithResponse(String url, String responseFile) {
        stubFor(post(urlEqualTo(url))
                .withHeader("Accept", equalTo("application/json"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(readFileBody(responseFile))));
    }

    public static void stubNotFoundResponse(String url, String requestFile) {
        stubErrorResponse(url, requestFile, 404);
    }

    public static void stubUnauthorizedResponse(String url, String requestFile) {
        stubErrorResponse(url, requestFile, 401);
    }

    public static void stubBadRequestResponse(String url, String requestFile) {
        stubErrorResponse(url, requestFile, 400);
    }

    public static void stubForbiddenResponse(String url, String requestFile) {
        stubErrorResponse(url, requestFile, 403);
    }

    public static void stubErrorResponse(String url, String requestFile, int errorStatus) {
        stubFor(post(urlEqualTo(url))
                .withHeader("Accept", equalTo("application/json"))
                .withRequestBody(equalToJson(readFileBody(requestFile), true, true))
                .willReturn(aResponse()
                        .withStatus(errorStatus)
                        .withHeader("Content-Type", "application/json")
                        .withBody("Not found")));
    }

    public static void stubRequestWithResponse(String urlEquals, String responseFile) {
        stubFor(get(urlPathEqualTo(urlEquals))
                .withHeader("Accept", equalTo("application/json"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(readFileBody(responseFile))));
    }

    public static void stubRequestWithResponse(String url, String requestFile, String responseFile) {
        stubFor(post(urlEqualTo(url))
                .withHeader("Accept", equalTo("application/json"))
                .withRequestBody(equalToJson(readFileBody(requestFile), true, true))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(readFileBody(responseFile))));
    }

    public static void stubStrictRequestWithResponse(String url, String requestFile, String responseFile) {
        stubFor(post(urlEqualTo(url))
                .withHeader("Accept", equalTo("application/json"))
                .withRequestBody(equalToJson(readFileBody(requestFile), false, false))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(readFileBody(responseFile))));
    }

    public static void stubSessionStatusWithState(String sessionId, String responseFile, String startState, String endState) {
        String urlEquals = "/session/" + sessionId;
        stubFor(get(urlEqualTo(urlEquals))
                .inScenario("session status")
                .whenScenarioStateIs(startState)
                .withHeader("Accept", equalTo("application/json"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(readFileBody(responseFile)))
                .willSetStateTo(endState)
        );
    }

    public static void stubPostErrorResponse(String url, int errorStatus) {
        stubFor(post(urlEqualTo(url))
                .withHeader("Accept", equalTo("application/json"))
                .willReturn(aResponse()
                        .withStatus(errorStatus)
                        .withHeader("Content-Type", "application/json")
                        .withBody("")));
    }

    private static String readFileBody(String fileName) {
        ClassLoader classLoader = SmartIdRestServiceStubs.class.getClassLoader();
        URL resource = classLoader.getResource(fileName);
        assertNotNull(resource, "File not found: " + fileName);
        File file = new File(resource.getFile());
        try {
            return Files.readString(file.toPath());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

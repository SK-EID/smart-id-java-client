package ee.sk.smartid;

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

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.net.URL;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.Assert.assertNotNull;

public class SmartIdRestServiceStubs {

  public static void stubNotFoundResponse(String urlEquals) {
    stubFor(get(urlEqualTo(urlEquals))
        .withHeader("Accept", equalTo("application/json"))
        .willReturn(aResponse()
            .withStatus(404)
            .withHeader("Content-Type", "application/json")
            .withBody("Not found")));
  }

  public static void stubNotFoundResponse(String url, String requestFile) throws IOException {
    stubErrorResponse(url, requestFile, 404);
  }

  public static void stubUnauthorizedResponse(String url, String requestFile) throws IOException {
    stubErrorResponse(url, requestFile, 401);
  }

  public static void stubBadRequestResponse(String url, String requestFile) throws IOException {
    stubErrorResponse(url, requestFile, 400);
  }

  public static void stubForbiddenResponse(String url, String requestFile) throws IOException {
    stubErrorResponse(url, requestFile, 403);
  }

  public static void stubErrorResponse(String url, String requestFile, int errorStatus) throws IOException {
    stubFor(post(urlEqualTo(url))
        .withHeader("Accept", equalTo("application/json"))
        .withRequestBody(equalToJson(readFileBody(requestFile)))
        .willReturn(aResponse()
            .withStatus(errorStatus)
            .withHeader("Content-Type", "application/json")
            .withBody("Not found")));
  }

  public static void stubRequestWithResponse(String urlEquals, String responseFile) throws IOException {
    stubFor(get(urlPathEqualTo(urlEquals))
        .withHeader("Accept", equalTo("application/json"))
        .willReturn(aResponse()
            .withStatus(200)
            .withHeader("Content-Type", "application/json")
            .withBody(readFileBody(responseFile))));
  }

  public static void stubRequestWithResponse(String url, String requestFile, String responseFile) throws IOException {
    stubFor(post(urlEqualTo(url))
        .withHeader("Accept", equalTo("application/json"))
        .withRequestBody(equalToJson(readFileBody(requestFile)))
        .willReturn(aResponse()
            .withStatus(200)
            .withHeader("Content-Type", "application/json")
            .withBody(readFileBody(responseFile))));
  }

  public static void stubSessionStatusWithState(String sessionId, String responseFile, String startState, String endState) throws IOException {
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

  private static String readFileBody(String fileName) throws IOException {
    ClassLoader classLoader = SmartIdRestServiceStubs.class.getClassLoader();
    URL resource = classLoader.getResource(fileName);
    assertNotNull("File not found: " + fileName, resource);
    File file = new File(resource.getFile());
    return FileUtils.readFileToString(file, "UTF-8");
  }
}

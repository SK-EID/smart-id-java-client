package ee.sk.smartid;

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.net.URL;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.Assert.assertNotNull;

public class NetworkStubs {

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
    stubFor(get(urlEqualTo(urlEquals))
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

  private static String readFileBody(String fileName) throws IOException {
    ClassLoader classLoader = NetworkStubs.class.getClassLoader();
    URL resource = classLoader.getResource(fileName);
    assertNotNull("File not found: " + fileName, resource);
    File file = new File(resource.getFile());
    return FileUtils.readFileToString(file, "UTF-8");
  }
}

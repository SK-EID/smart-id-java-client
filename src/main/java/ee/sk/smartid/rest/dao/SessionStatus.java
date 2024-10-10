package ee.sk.smartid.rest.dao;

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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;
import java.util.Arrays;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SessionStatus implements Serializable {

  private String state;
  private SessionResult result;
  private SessionSignature signature;

  private SessionCertificate cert;
  private String[] ignoredProperties = {};

  private String interactionFlowUsed;
  private String deviceIpAddress;

  public String getState() {
    return state;
  }

  public void setState(String state) {
    this.state = state;
  }

  public SessionResult getResult() {
    return result;
  }

  public void setResult(SessionResult result) {
    this.result = result;
  }

  public SessionCertificate getCert() {
    return cert;
  }

  public void setCert(SessionCertificate cert) {
    this.cert = cert;
  }

  public SessionSignature getSignature() {
    return signature;
  }

  public void setSignature(SessionSignature signature) {
    this.signature = signature;
  }

  public String[] getIgnoredProperties() {
    return Arrays.copyOf(ignoredProperties, ignoredProperties.length);
  }

  public void setIgnoredProperties(String[] ignoredProperties) {
    this.ignoredProperties = Arrays.copyOf(ignoredProperties, ignoredProperties.length);
  }

  public String getInteractionFlowUsed() {
    return interactionFlowUsed;
  }

  public void setInteractionFlowUsed(String interactionFlowUsed) {
    this.interactionFlowUsed = interactionFlowUsed;
  }

  /**
   * IP-address of the device running the App.
   * <p>
   * Present only if withShareMdClientIpAddress() was specified with the request
   * Also, the RelyingParty must be subscribed for the service.
   * Also, the data must be available (e.g. not present in case state is TIMEOUT).
   * @see <a href="https://github.com/SK-EID/smart-id-documentation#238-mobile-device-ip-sharing">Mobile Device IP sharing</a>
   *
   * @return IP address of the device running Smart-ID app (or null if not returned)
   */
  public String getDeviceIpAddress() {
    return deviceIpAddress;
  }

  public void setDeviceIpAddress(String deviceIpAddress) {
    this.deviceIpAddress = deviceIpAddress;
  }

}

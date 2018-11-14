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

import java.io.Serializable;

public class NationalIdentity implements Serializable {

  private String countryCode;
  private String nationalIdentityNumber;

  public NationalIdentity() {
  }

  public NationalIdentity(String countryCode, String nationalIdentityNumber) {
    this.countryCode = countryCode;
    this.nationalIdentityNumber = nationalIdentityNumber;
  }

  public String getCountryCode() {
    return countryCode;
  }

  public void setCountryCode(String countryCode) {
    this.countryCode = countryCode;
  }

  public String getNationalIdentityNumber() {
    return nationalIdentityNumber;
  }

  public void setNationalIdentityNumber(String nationalIdentityNumber) {
    this.nationalIdentityNumber = nationalIdentityNumber;
  }

  @Override
  public String toString() {
    return "NationalIdentity{" +
        "countryCode='" + countryCode + '\'' +
        ", nationalIdentityNumber='" + nationalIdentityNumber + '\'' +
        '}';
  }
}

package ee.sk.smartid.rest.dao;

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

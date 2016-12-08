package ee.sk.smartid.rest.dao;

import java.io.Serializable;

public class NationalIdentity implements Serializable {

  private String country;
  private String nationalIdentityNumber;

  public NationalIdentity() {
  }

  public NationalIdentity(String country, String nationalIdentityNumber) {
    this.country = country;
    this.nationalIdentityNumber = nationalIdentityNumber;
  }

  public String getCountry() {
    return country;
  }

  public void setCountry(String country) {
    this.country = country;
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
        "country='" + country + '\'' +
        ", nationalIdentityNumber='" + nationalIdentityNumber + '\'' +
        '}';
  }
}

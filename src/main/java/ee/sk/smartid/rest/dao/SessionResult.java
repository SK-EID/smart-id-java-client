package ee.sk.smartid.rest.dao;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SessionResult implements Serializable {

  private String endResult;
  private String documentNumber;

  public String getDocumentNumber() {
    return documentNumber;
  }

  public void setDocumentNumber(String documentNumber) {
    this.documentNumber = documentNumber;
  }

  public String getEndResult() {
    return endResult;
  }

  public void setEndResult(String endResult) {
    this.endResult = endResult;
  }
}

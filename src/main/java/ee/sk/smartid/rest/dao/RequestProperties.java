package ee.sk.smartid.rest.dao;

import java.io.Serializable;

public class RequestProperties implements Serializable {

  private boolean vcChoice;

  public boolean isVcChoice() {
    return vcChoice;
  }

  public void setVcChoice(boolean vcChoice) {
    this.vcChoice = vcChoice;
  }

  @Override
  public String toString() {
    return "RequestProperties{" +
            "vcChoice='" + vcChoice + '\'' +
            '}';
  }
}

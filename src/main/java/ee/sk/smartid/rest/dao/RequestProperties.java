package ee.sk.smartid.rest.dao;

import java.io.Serializable;

/**
 * request.setVcChoice(true) was removed in Smart-ID API 2.0 and replaced by:
 * request.setAllowedInteractionsOrder(Collections.singletonList(AllowedInteraction.verificationCodeChoice("insert displayText here")));
 */
public class RequestProperties implements Serializable {

  @Override
  public String toString() {
    return "RequestProperties{}";
  }

}

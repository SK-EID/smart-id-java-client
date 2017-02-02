package ee.sk.smartid;

public enum HashType {

  SHA256("SHA-256", "SHA256"),
  SHA384("SHA-384", "SHA384"),
  SHA512("SHA-512", "SHA512");

  private String algorithmName;
  private String hashTypeName;

  HashType(String algorithmName, String hashTypeName) {
    this.algorithmName = algorithmName;
    this.hashTypeName = hashTypeName;
  }

  public String getAlgorithmName() {
    return algorithmName;
  }

  public String getHashTypeName() {
    return hashTypeName;
  }
}

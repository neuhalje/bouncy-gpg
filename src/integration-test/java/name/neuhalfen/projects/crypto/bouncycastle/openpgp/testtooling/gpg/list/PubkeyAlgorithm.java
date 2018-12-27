package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list;


public enum PubkeyAlgorithm {
  RSA(1),
  UNKNOWN(-1);

  private final int id;

  PubkeyAlgorithm(final int id) {
    this.id = id;
  }

  public static PubkeyAlgorithm forField(int fieldValue) {

    for (final PubkeyAlgorithm v : values()) {
      if (v.id == fieldValue) {
        return v;
      }
    }
    return UNKNOWN;
  }

  public static PubkeyAlgorithm forField(String fieldValue) {
    try {
      return PubkeyAlgorithm.forField(Integer.parseInt(fieldValue));
    } catch (NumberFormatException e) {
      return PubkeyAlgorithm.UNKNOWN;
    }
  }
}

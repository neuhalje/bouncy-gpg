package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;

public class PublicKeySize {

  /**
   * Key sizes for RSA
   */
  public enum RSA implements KeySize {
    RSA_1024_BIT(1024),
    RSA_2048_BIT(2048),
    RSA_3072_BIT(3072),
    RSA_4096_BIT(4096),
    RSA_8192_BIT(8192);


    private final int size;

    RSA(int size) {
      this.size = size;
    }

    @Override
    public int getSize() {
      return size;
    }
  }

  /**
   * Key sizes for ElGamal ECC keys
   */
  @SuppressWarnings({"PMD.ClassNamingConventions"})
  public enum DSA_ElGamal implements KeySize {
    DSA_1024_BIT(1024),
    DSA_2048_BIT(2048),
    DSA_3072_BIT(3072);


    private final int size;

    DSA_ElGamal(int size) {
      this.size = size;
    }

    @Override
    public int getSize() {
      return size;
    }
  }

  public interface KeySize {

    /**
     * Key size in bits
     *
     * @return size in bits
     */
    int getSize();
  }
}

package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;


public final class PGPAlgorithmSuite {

  private final PGPHashAlgorithms hashAlgorithmCode;
  private final PGPSymmetricEncryptionAlgorithms symmetricEncryptionAlgorithmCode;
  private final PGPCompressionAlgorithms compressionEncryptionAlgorithmCode;

  public PGPAlgorithmSuite(PGPHashAlgorithms hashAlgorithmCode,
      PGPSymmetricEncryptionAlgorithms symmetricEncryptionAlgorithmCode,
      PGPCompressionAlgorithms compressionEncryptionAlgorithmCode) {

    if (hashAlgorithmCode == null) {
      throw new IllegalArgumentException("hashAlgorithmCode must not be null");
    }
    if (symmetricEncryptionAlgorithmCode == null) {
      throw new IllegalArgumentException("symmetricEncryptionAlgorithmCode must not be null");
    }
    if (compressionEncryptionAlgorithmCode == null) {
      throw new IllegalArgumentException("compressionEncryptionAlgorithmCode must not be null");
    }

    this.hashAlgorithmCode = hashAlgorithmCode;
    this.symmetricEncryptionAlgorithmCode = symmetricEncryptionAlgorithmCode;
    this.compressionEncryptionAlgorithmCode = compressionEncryptionAlgorithmCode;
  }

  public PGPHashAlgorithms getHashAlgorithmCode() {
    return hashAlgorithmCode;
  }

  public PGPSymmetricEncryptionAlgorithms getSymmetricEncryptionAlgorithmCode() {
    return symmetricEncryptionAlgorithmCode;
  }

  public PGPCompressionAlgorithms getCompressionEncryptionAlgorithmCode() {
    return compressionEncryptionAlgorithmCode;
  }

  public String toString() {
    return String.format("%s/%s/%s", hashAlgorithmCode, symmetricEncryptionAlgorithmCode,
        compressionEncryptionAlgorithmCode);
  }
}

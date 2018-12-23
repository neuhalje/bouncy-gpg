package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;


import static java.util.Objects.requireNonNull;

public final class PGPAlgorithmSuite {

  private final PGPHashAlgorithms hashAlgorithmCode;
  private final PGPSymmetricEncryptionAlgorithms symmetricEncryptionAlgorithmCode;
  private final PGPCompressionAlgorithms compressionEncryptionAlgorithmCode;

  public PGPAlgorithmSuite(PGPHashAlgorithms hashAlgorithmCode,
      PGPSymmetricEncryptionAlgorithms symmetricEncryptionAlgorithmCode,
      PGPCompressionAlgorithms compressionEncryptionAlgorithmCode) {

    requireNonNull(hashAlgorithmCode, "hashAlgorithmCode must not be null");
    requireNonNull(symmetricEncryptionAlgorithmCode,
        "symmetricEncryptionAlgorithmCode must not be null");
    requireNonNull(compressionEncryptionAlgorithmCode,
        "compressionEncryptionAlgorithmCode must not be null");

    this.hashAlgorithmCode = hashAlgorithmCode;
    this.symmetricEncryptionAlgorithmCode = symmetricEncryptionAlgorithmCode;
    this.compressionEncryptionAlgorithmCode = compressionEncryptionAlgorithmCode;
  }

  /**
   * @return the hashing algorithm to be used
   */
  public PGPHashAlgorithms getHashAlgorithmCode() {
    return hashAlgorithmCode;
  }

  /**
   * @return the symmetrical encryption algorithm to be used
   */
  public PGPSymmetricEncryptionAlgorithms getSymmetricEncryptionAlgorithmCode() {
    return symmetricEncryptionAlgorithmCode;
  }

  /**
   * @deprecated use getCompressionAlgorithmCode
   * @return the compression algorithm to be used
   */
  @Deprecated()
  public PGPCompressionAlgorithms getCompressionEncryptionAlgorithmCode() {
    return getCompressionAlgorithmCode();
  }

  public PGPCompressionAlgorithms getCompressionAlgorithmCode() {
    return compressionEncryptionAlgorithmCode;
  }

  @Override
  public String toString() {
    return String.format("%s/%s/%s", hashAlgorithmCode, symmetricEncryptionAlgorithmCode,
        compressionEncryptionAlgorithmCode);
  }
}

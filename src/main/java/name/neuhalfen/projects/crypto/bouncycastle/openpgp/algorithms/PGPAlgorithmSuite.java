package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;


import name.neuhalfen.projects.crypto.internal.Preconditions;

public final class PGPAlgorithmSuite {

  private final PGPHashAlgorithms hashAlgorithmCode;
  private final PGPSymmetricEncryptionAlgorithms symmetricEncryptionAlgorithmCode;
  private final PGPCompressionAlgorithms compressionEncryptionAlgorithmCode;

  public PGPAlgorithmSuite(PGPHashAlgorithms hashAlgorithmCode,
      PGPSymmetricEncryptionAlgorithms symmetricEncryptionAlgorithmCode,
      PGPCompressionAlgorithms compressionEncryptionAlgorithmCode) {

    Preconditions.checkNotNull(hashAlgorithmCode, "hashAlgorithmCode must not be null");
    Preconditions.checkNotNull(symmetricEncryptionAlgorithmCode,
        "symmetricEncryptionAlgorithmCode must not be null");
    Preconditions.checkNotNull(compressionEncryptionAlgorithmCode,
        "compressionEncryptionAlgorithmCode must not be null");

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

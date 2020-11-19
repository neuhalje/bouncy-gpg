package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;

@SuppressWarnings({"PMD.ClassNamingConventions"})
public final class DefaultPGPAlgorithmSuites {

  /**
   * GPG default algorithms.
   */
  private static final PGPAlgorithmSuite DEFAULT_GPG = new PGPAlgorithmSuite(
      PGPHashAlgorithms.SHA1,
      PGPSymmetricEncryptionAlgorithms.CAST5,
      PGPCompressionAlgorithms.ZLIB);

  /**
   * GPG strong crypto algorithms.
   */
  private static final PGPAlgorithmSuite STRONG_GPG = new PGPAlgorithmSuite(
      PGPHashAlgorithms.SHA_256,
      PGPSymmetricEncryptionAlgorithms.AES_128,
      PGPCompressionAlgorithms.ZLIB);

  /**
   * Algorithm suite for XEP-0373: OpenPGP for XMPP.
   */
  private static final PGPAlgorithmSuite DEFAULT_OX = new PGPAlgorithmSuite(
      PGPHashAlgorithms.SHA_256,
      PGPSymmetricEncryptionAlgorithms.AES_128,
      PGPCompressionAlgorithms.UNCOMPRESSED);

  // no construction
  private DefaultPGPAlgorithmSuites() {
  }

  /**
   * The default GPG suite: SHA-1,  CAST 5, and ZLIB.
   *
   * @return suite
   */
  public static PGPAlgorithmSuite defaultSuiteForGnuPG() {
    return DEFAULT_GPG;
  }

  /**
   * A sensible suite with strong algorithms:  SHA-256,  AES-128, and ZLIB.
   *
   * @return suite
   */
  public static PGPAlgorithmSuite strongSuite() {
    return STRONG_GPG;
  }

  /**
  * Algorithm suite for XEP-0373: OpenPGP for XMPP.
  */
  public static PGPAlgorithmSuite oxSuite() {
    return DEFAULT_OX;
  }

}

package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;

/**
 * Typed enum to describe the hash algorithms supported by GPG.
 *
 * @see CompressionAlgorithmTags
 */
public enum PGPCompressionAlgorithms {
  /**
   * No compression.
   */
  UNCOMPRESSED(CompressionAlgorithmTags.UNCOMPRESSED),

  /**
   * ZIP (RFC 1951) compression. Unwrapped DEFLATE.
   */
  ZIP(CompressionAlgorithmTags.ZIP),

  /**
   * ZLIB (RFC 1950) compression. DEFLATE with a wrapper for better error detection.
   */
  ZLIB(CompressionAlgorithmTags.ZLIB),

  /**
   * BZIP2 compression. Better compression than ZIP but much slower to compress and decompress.
   */
  BZIP2(CompressionAlgorithmTags.BZIP2);

  private final int algorithmId;

  /**
   * Returns the corresponding BouncyCastle  algorithm tag.
   *
   * @return algorithmId
   * @see CompressionAlgorithmTags
   */
  public int getAlgorithmId() {
    return algorithmId;
  }

  PGPCompressionAlgorithms(int algorithmId) {
    this.algorithmId = algorithmId;
  }
}

package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;


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


  public final int id;

  PGPCompressionAlgorithms(int id) {
    this.id = id;
  }
}

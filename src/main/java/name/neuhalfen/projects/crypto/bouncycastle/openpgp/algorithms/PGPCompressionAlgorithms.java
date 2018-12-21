package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;

import java.util.Set;
import name.neuhalfen.projects.crypto.internal.SetUtils;
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

  PGPCompressionAlgorithms(int algorithmId) {
    this.algorithmId = algorithmId;
  }

  /**
   * Returns the corresponding BouncyCastle  algorithm tag.
   *
   * @return algorithmId
   *
   * @see CompressionAlgorithmTags
   */
  public int getAlgorithmId() {
    return algorithmId;
  }

  private final static Set<PGPCompressionAlgorithms> RECOMMENDED_ALGORITHMS = SetUtils
      .unmodifiableSet(BZIP2, ZLIB, ZIP, UNCOMPRESSED);

  private final static int[] RECOMMENDED_ALGORITHM_IDS =
      RECOMMENDED_ALGORITHMS.stream().mapToInt(algorithm -> algorithm.algorithmId).toArray();

  public static Set<PGPCompressionAlgorithms> recommendedAlgorithms() {
    return RECOMMENDED_ALGORITHMS;
  }

  public static int[] recommendedAlgorithmIds() {
    return RECOMMENDED_ALGORITHM_IDS;
  }
}

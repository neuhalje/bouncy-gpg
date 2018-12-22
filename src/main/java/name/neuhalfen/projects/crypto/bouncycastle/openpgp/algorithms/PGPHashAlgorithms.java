package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import org.bouncycastle.bcpg.HashAlgorithmTags;


/**
 * Typed enum to describe the hash algorithms supported by GPG.
 *
 * @see HashAlgorithmTags
 */
public enum PGPHashAlgorithms {
  /**
   * MD5. [INSECURE]
   */
  MD5(HashAlgorithmTags.MD5, true),

  /**
   * SHA1. [INSECURE]
   */
  SHA1(HashAlgorithmTags.SHA1, true),

  /**
   * SHA-224.
   */
  SHA_224(HashAlgorithmTags.SHA224),

  /**
   * SHA-256.
   */
  SHA_256(HashAlgorithmTags.SHA256),

  /**
   * SHA-384.
   */
  SHA_384(HashAlgorithmTags.SHA384),

  /**
   * SHA-512.
   */
  SHA_512(HashAlgorithmTags.SHA512),

  /**
   * RIPEMD-160.
   */
  RIPEMD160(HashAlgorithmTags.RIPEMD160),

  /**
   * TIGER-192.
   */
  TIGER_192(HashAlgorithmTags.TIGER_192),

  /**
   * HAVAL_5_160. [INSECURE]
   */
  HAVAL_5_160(HashAlgorithmTags.HAVAL_5_160, true);

  private final static Set<PGPHashAlgorithms> RECOMMENDED_ALGORITHMS = Collections
      .unmodifiableSet(
          Arrays.stream(
              PGPHashAlgorithms.values()).filter(alg -> !alg.insecure)
              .collect(Collectors.toSet()));
  private final static int[] RECOMMENDED_ALGORITHM_IDS =
      RECOMMENDED_ALGORITHMS.stream().mapToInt(algorithm -> algorithm.algorithmId).toArray();
  private final int algorithmId;
  private final boolean insecure;

  PGPHashAlgorithms(int algorithmId) {
    this(algorithmId, false);
  }

  PGPHashAlgorithms(int algorithmId, boolean insecure) {
    this.algorithmId = algorithmId;
    this.insecure = insecure;
  }

  public static Set<PGPHashAlgorithms> recommendedAlgorithms() {
    return RECOMMENDED_ALGORITHMS;
  }

  public static int[] recommendedAlgorithmIds() {
    return RECOMMENDED_ALGORITHM_IDS.clone();
  }

  /**
   * Returns the corresponding BouncyCastle  algorithm tag.
   *
   * @return algorithmId
   *
   * @see HashAlgorithmTags
   */
  public int getAlgorithmId() {
    return algorithmId;
  }

  /**
   * Known insecurities. Is this algorithm KNOWN to be broken or are there any known attacks on it?
   * A value of 'false' does not guarantee, that the algorithm is safe!
   *
   * @return true: insecure,do not use; false: please double check if the algorithm is
   *     appropriate for you.
   */
  public boolean isInsecure() {
    return insecure;
  }
}

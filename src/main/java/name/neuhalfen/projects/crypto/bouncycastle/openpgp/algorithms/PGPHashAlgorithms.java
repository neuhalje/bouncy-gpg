package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;

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

  private final int algorithmId;

  private final boolean insecure;

  /**
   * Returns the corresponding BouncyCastle  algorithm tag.
   *
   * @return algorithmId
   * @see HashAlgorithmTags
   */
  public int getAlgorithmId() {
    return algorithmId;
  }

  /**
   * Is this algorithm KNOWN to be broken or are there any known attacks on it?
   * A value of 'false' does not guarantee, that the algorithm is safe!
   * @return true: insecure,do not use; false: please double check if the algorithm is appropriate for you.
   */
  public boolean isInsecure() {
    return insecure;
  }


  PGPHashAlgorithms(int algorithmId) {
    this(algorithmId, false);
  }

  PGPHashAlgorithms(int algorithmId, boolean insecure) {
    this.algorithmId = algorithmId;
    this.insecure = insecure;
  }
}

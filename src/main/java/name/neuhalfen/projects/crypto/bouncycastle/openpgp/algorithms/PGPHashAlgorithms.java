package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;

import org.bouncycastle.bcpg.HashAlgorithmTags;


public enum PGPHashAlgorithms {
  MD5(HashAlgorithmTags.MD5, true),
  SHA1(HashAlgorithmTags.SHA1, true),
  SHA_224(HashAlgorithmTags.SHA224),
  SHA_256(HashAlgorithmTags.SHA256),
  SHA_384(HashAlgorithmTags.SHA384),
  SHA_512(HashAlgorithmTags.SHA512),
  RIPEMD160(HashAlgorithmTags.RIPEMD160),
  TIGER_192(HashAlgorithmTags.TIGER_192),
  HAVAL_5_160(HashAlgorithmTags.HAVAL_5_160, true);

  public final int id;

  /**
   * Is this algorithm KNOWN to be broken or are there any known attacks on it? <p> DO NOT TRUST
   * THIS JUDGEMENT! <p> A value of 'false' does not guarantee, that the algorithm is safe!
   */
  @SuppressWarnings("WeakerAccess")
  public final boolean insecure;

  PGPHashAlgorithms(int id) {
    this(id, false);
  }

  PGPHashAlgorithms(int id, boolean insecure) {
    this.id = id;
    this.insecure = insecure;
  }
}

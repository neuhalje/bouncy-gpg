package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

/**
 * Typed enum to describe the symmetric encryption algorithms supported by GPG.
 *
 * @see SymmetricKeyAlgorithmTags
 */
public enum PGPSymmetricEncryptionAlgorithms {

  /**
   * Plaintext or unencrypted data. [INSECURE]
   */
  NULL(SymmetricKeyAlgorithmTags.NULL, true),

  /**
   * IDEA [IDEA].  [INSECURE]
   */
  IDEA(SymmetricKeyAlgorithmTags.IDEA, true),

  /**
   * Triple-DES (DES-EDE, as per spec -168 bit key derived from 192). [INSECURE]: 64 bit blocksize.
   * https://en.wikipedia.org/wiki/Triple_DES#cite_note-NIST57r4-12
   */
  TRIPLE_DES(SymmetricKeyAlgorithmTags.TRIPLE_DES, false),

  /**
   * CAST5 (128 bit key, as per RFC 2144)  [INSECURE]: 64 bit blocksize.
   */
  CAST5(SymmetricKeyAlgorithmTags.CAST5, true),

  /**
   * Blowfish (128 bit key, 16 rounds) [BLOWFISH]  [INSECURE]: 64 bit blocksize.
   */
  BLOWFISH(SymmetricKeyAlgorithmTags.BLOWFISH, true),

  /**
   * SAFER-SK128 (13 rounds) [SAFER] [INSECURE]:  64 bit blocksize.
   */
  SAFER(SymmetricKeyAlgorithmTags.SAFER, true),

  /**
   * Reserved for DES/SK. [INSECURE]
   */
  DES(SymmetricKeyAlgorithmTags.DES, true),

  /**
   * Reserved for AES with 128-bit key.
   */
  AES_128(SymmetricKeyAlgorithmTags.AES_128, false),

  /**
   * Reserved for AES with 192-bit key.
   */
  AES_192(SymmetricKeyAlgorithmTags.AES_192, false),

  /**
   * Reserved for AES with 256-bit key.
   */
  AES_256(SymmetricKeyAlgorithmTags.AES_256, false),

  /**
   * Reserved for Twofish.
   */
  TWOFISH(SymmetricKeyAlgorithmTags.TWOFISH, false),

  /**
   * Reserved for Camellia with 128-bit key.
   */
  CAMELLIA_128(SymmetricKeyAlgorithmTags.CAMELLIA_128, false),

  /**
   * Reserved for Camellia with 192-bit key.
   */
  CAMELLIA_192(SymmetricKeyAlgorithmTags.CAMELLIA_192, false),

  /**
   * Reserved for Camellia with 256-bit key.
   */
  CAMELLIA_256(SymmetricKeyAlgorithmTags.CAMELLIA_256, false);


  private static final Set<PGPSymmetricEncryptionAlgorithms> RECOMMENDED_ALGORITHMS = Collections
      .unmodifiableSet(
          Arrays.stream(
              PGPSymmetricEncryptionAlgorithms.values())
              .filter(alg -> !alg.insecure)
              .collect(Collectors.toSet()));
  private static final int[] RECOMMENDED_ALGORITHM_IDS =
      RECOMMENDED_ALGORITHMS.stream().mapToInt(algorithm -> algorithm.algorithmId).toArray();
  private final int algorithmId;
  private final boolean insecure;

  PGPSymmetricEncryptionAlgorithms(int algorithmId, boolean insecure) {
    this.algorithmId = algorithmId;
    this.insecure = insecure;
  }

  public static Set<PGPSymmetricEncryptionAlgorithms> recommendedAlgorithms() {
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
   * @see SymmetricKeyAlgorithmTags
   */
  public int getAlgorithmId() {
    return algorithmId;
  }

  /**
   * Is this algorithm KNOWN to be broken or are there any known attacks on it?
   * A value of 'false' does not guarantee, that the algorithm is safe!
   *
   * @return true: insecure,do not use; false: please double check if the algorithm is appropriate
   *     for you.
   */
  public boolean isInsecure() {
    return insecure;
  }
}

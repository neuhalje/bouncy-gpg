package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;

import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;

public enum PublicKeyType {
  /**
   * RSA key marked for use in encryption and signatures.
   */
  RSA_GENERAL(PublicKeyAlgorithmTags.RSA_GENERAL, "RSA"),

  /**
   * RSA key marked for use in encryption only.
   */
  RSA_ENCRYPT(PublicKeyAlgorithmTags.RSA_ENCRYPT, "RSA"),

  /**
   * RSA key marked for use in signature only.
   */
  RSA_SIGN(PublicKeyAlgorithmTags.RSA_SIGN, "RSA"),

  /**
   * El Gamal key marked for use in encryption only.
   */
  ELGAMAL_ENCRYPT(PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT, "ElGamal"),

  /**
   * DSA key (signing only)
   * https://de.wikipedia.org/wiki/Digital_Signature_Algorithm
   */
  DSA(PublicKeyAlgorithmTags.DSA, "DSA"),

  /*
   * Elliptic Curve keys
   */
    /*
    // disabled until test cases are written

    ECDH(           PublicKeyAlgorithmTags.ECDH,            "ECDH"),
    ECDSA(          PublicKeyAlgorithmTags.ECDSA,           "ECDSA"),
    ELGAMAL_GENERAL(PublicKeyAlgorithmTags.ELGAMAL_GENERAL, "ElGamal"),
    DIFFIE_HELLMAN( PublicKeyAlgorithmTags.DIFFIE_HELLMAN,  "DiffieHellman");
    */;

  private static final Map<Integer, PublicKeyType> MAP = new HashMap<>();

  static {
    for (final PublicKeyType a : PublicKeyType.values()) {
      MAP.put(a.getId(), a);
    }
  }

  @SuppressWarnings({"PMD.FieldNamingConventions"})
  private final int rfc4880_ID;
  private final String algorithmName;

  PublicKeyType(int typeId, String algoName) {
    this.rfc4880_ID = typeId;
    this.algorithmName = algoName;
  }

  /**
   * Map a PublicKeyAlgorithmTags.XXX tag to the enum value.
   *
   * @param typeId one of the supported tags.
   *
   * @return enum
   *
   * @throws IllegalArgumentException when the typeId is unknown
   * @see PublicKeyAlgorithmTags
   */
  public static PublicKeyType fromId(int typeId) {
    final PublicKeyType algorithm = MAP.get(typeId);
    if (algorithm == null) {
      throw new IllegalArgumentException("Unknown id: " + typeId);
    }
    return algorithm;
  }

  /**
   * Return the bouncy castle algorithm identifier.
   *
   * @return bouncy castle algorithm identifier
   *
   * @see PublicKeyAlgorithmTags
   */
  public int getId() {
    return rfc4880_ID;
  }

  /**
   * Return the algorithm name (RSA, ElGamal, ..). Useful for display purposes.
   *
   * @return name of the algorithm
   */
  public String getAlgorithmName() {
    return algorithmName;
  }
}

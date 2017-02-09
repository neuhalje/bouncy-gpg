package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;


public enum PGPSymmetricEncryptionAlgorithms {

    /**
     * Plaintext or unencrypted data
     */
    NULL(SymmetricKeyAlgorithmTags.NULL, true),
    /**
     * IDEA [IDEA]
     */
    IDEA(SymmetricKeyAlgorithmTags.IDEA, true),

    /**
     * Triple-DES (DES-EDE, as per spec -168 bit key derived from 192)
     */
    TRIPLE_DES(SymmetricKeyAlgorithmTags.TRIPLE_DES, true),

    /**
     * CAST5 (128 bit key, as per RFC 2144)
     * <p>
     * Insecure: 64 bit blocksize
     */
    CAST5(SymmetricKeyAlgorithmTags.CAST5, true),

    /**
     * Blowfish (128 bit key, 16 rounds) [BLOWFISH]
     * <p>
     * Insecure: 64 bit blocksize
     */
    BLOWFISH(SymmetricKeyAlgorithmTags.BLOWFISH, true),

    /**
     * SAFER-SK128 (13 rounds) [SAFER]
     * <p>
     * Insecure: 64 bit blocksize
     */
    SAFER(SymmetricKeyAlgorithmTags.SAFER, true),
    /**
     * Reserved for DES/SK
     */
    DES(SymmetricKeyAlgorithmTags.DES, true),
    /**
     * Reserved for AES with 128-bit key
     */
    AES_128(SymmetricKeyAlgorithmTags.AES_128, false),
    /**
     * Reserved for AES with 192-bit key
     */
    AES_192(SymmetricKeyAlgorithmTags.AES_192, false),

    /**
     * Reserved for AES with 256-bit key
     */
    AES_256(SymmetricKeyAlgorithmTags.AES_256, false),

    /**
     * Reserved for Twofish
     */
    TWOFISH(SymmetricKeyAlgorithmTags.TWOFISH, false),

    /**
     * Reserved for Camellia with 128-bit key
     */
    CAMELLIA_128(SymmetricKeyAlgorithmTags.CAMELLIA_128, false),


    /**
     * Reserved for Camellia with 192-bit key
     */
    CAMELLIA_192(SymmetricKeyAlgorithmTags.CAMELLIA_192, false),

    /**
     * Reserved for Camellia with 256-bit key
     */
    CAMELLIA_256(SymmetricKeyAlgorithmTags.CAMELLIA_256, false);


    public final int id;

    /**
     * Is this algorithm KNOWN to be broken or are there any known attacks on it?
     * <p>
     * DO NOT TRUST THIS JUDGEMENT!
     * <p>
     * A value of 'false' does not guarantee, that the algorithm is safe!
     */
    public final boolean insecure;


    PGPSymmetricEncryptionAlgorithms(int id, boolean insecure) {
        this.id = id;
        this.insecure = insecure;
    }

}

package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;


public class DefaultPGPAlgorithmSuites {

    private final static PGPAlgorithmSuite DEFAULT_GPG = new PGPAlgorithmSuite(PGPHashAlgorithms.SHA1, PGPSymmetricEncryptionAlgorithms.AES_128, PGPCompressionAlgorithms.ZLIB);

    public static PGPAlgorithmSuite defaultSuiteForGnuPG() {
        return DEFAULT_GPG;
    }

}

package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;


public class PGPAlgorithmSuite {

    private final PGPHashAlgorithms hashAlgorithmCode;
    private final PGPSymmetricEncryptionAlgorithms symmetricEncryptionAlgorithmCode;
    private final PGPCompressionAlgorithms compressionEncryptionAlgorithmCode;

    public PGPAlgorithmSuite(PGPHashAlgorithms hashAlgorithmCode, PGPSymmetricEncryptionAlgorithms symmetricEncryptionAlgorithmCode, PGPCompressionAlgorithms compressionEncryptionAlgorithmCode) {
        this.hashAlgorithmCode = hashAlgorithmCode;
        this.symmetricEncryptionAlgorithmCode = symmetricEncryptionAlgorithmCode;
        this.compressionEncryptionAlgorithmCode = compressionEncryptionAlgorithmCode;
    }

    public PGPHashAlgorithms getHashAlgorithmCode() {
        return hashAlgorithmCode;
    }

    public PGPSymmetricEncryptionAlgorithms getSymmetricEncryptionAlgorithmCode() {
        return symmetricEncryptionAlgorithmCode;
    }

    public PGPCompressionAlgorithms getCompressionEncryptionAlgorithmCode() {
        return compressionEncryptionAlgorithmCode;
    }
}

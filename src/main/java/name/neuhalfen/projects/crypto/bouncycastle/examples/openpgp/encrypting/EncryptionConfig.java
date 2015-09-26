package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting;


import java.io.*;


public abstract class EncryptionConfig {
    private final String signatureSecretKeyPassphrase;
    private final String signatureSecretKeyId;
    private final String encryptionPublicKeyId;
    private final int pgpHashAlgorithmCode;
    private final int pgpSymmetricEncryptionAlgorithmCode;

    public static EncryptionConfig withKeyRingsFromFiles(final File publicKeyring,
                                                         final File secretKeyring,
                                                         String signatureSecretKeyId, String signatureSecretKeyPassphrase,
                                                         String encryptionPublicKeyId,
                                                         int pgpHashAlgorithmCode, int pgpSymmetricEncryptionAlgorithmCode) {

        return new EncryptionConfig(signatureSecretKeyId, signatureSecretKeyPassphrase, encryptionPublicKeyId, pgpHashAlgorithmCode, pgpSymmetricEncryptionAlgorithmCode) {

            final File publicKeyringFile = publicKeyring;
            final File secretKeyringFile = secretKeyring;

            @Override
            public InputStream getPublicKeyRing() throws IOException {
                return new FileInputStream(publicKeyringFile);
            }

            @Override
            public InputStream getSecretKeyRing() throws FileNotFoundException {
                return new FileInputStream(secretKeyringFile);
            }
        };
    }

    public static EncryptionConfig withKeyRingsFromResources(final ClassLoader classLoader, final String publicKeyring,
                                                             final String secretKeyring,
                                                             String signatureSecretKeyId, String signatureSecretKeyPassphrase,
                                                             String encryptionPublicKeyId,
                                                             int pgpHashAlgorithmCode, int pgpSymmetricEncryptionAlgorithmCode) {

        return new EncryptionConfig(signatureSecretKeyId, signatureSecretKeyPassphrase, encryptionPublicKeyId, pgpHashAlgorithmCode, pgpSymmetricEncryptionAlgorithmCode) {


            @Override
            public InputStream getPublicKeyRing() throws IOException {
                return classLoader.getResourceAsStream(publicKeyring);
            }

            @Override
            public InputStream getSecretKeyRing() throws FileNotFoundException {
                return classLoader.getResourceAsStream(secretKeyring);
            }
        };
    }


    protected EncryptionConfig(String signatureSecretKeyId, String signatureSecretKeyPassphrase,
                               String encryptionPublicKeyId,
                               int pgpHashAlgorithmCode, int pgpSymmetricEncryptionAlgorithmCode) {
        this.signatureSecretKeyPassphrase = signatureSecretKeyPassphrase;
        this.signatureSecretKeyId = signatureSecretKeyId;
        this.encryptionPublicKeyId = encryptionPublicKeyId;
        this.pgpHashAlgorithmCode = pgpHashAlgorithmCode;
        this.pgpSymmetricEncryptionAlgorithmCode = pgpSymmetricEncryptionAlgorithmCode;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("EncryptionConfig{");
        sb.append("signatureSecretKeyId='").append(signatureSecretKeyId).append('\'');
        sb.append(", encryptionPublicKeyId='").append(encryptionPublicKeyId).append('\'');
        sb.append(", pgpHashAlgorithmCode=").append(pgpHashAlgorithmCode);
        sb.append(", pgpSymmetricEncryptionAlgorithmCode=").append(pgpSymmetricEncryptionAlgorithmCode);
        sb.append(", signatureSecretKeyPassphrase='").append("*** secret ***").append('\'');
        sb.append('}');
        return sb.toString();
    }

    public abstract InputStream getPublicKeyRing() throws IOException;

    public abstract InputStream getSecretKeyRing() throws IOException;


    public String getSignatureSecretKeyPassphrase() {
        return signatureSecretKeyPassphrase;
    }

    public String getSignatureSecretKeyId() {
        return signatureSecretKeyId;
    }

    public String getEncryptionPublicKeyId() {
        return encryptionPublicKeyId;
    }

    public int getPgpHashAlgorithmCode() {
        return pgpHashAlgorithmCode;
    }

    public int getPgpSymmetricEncryptionAlgorithmCode() {
        return pgpSymmetricEncryptionAlgorithmCode;
    }

}

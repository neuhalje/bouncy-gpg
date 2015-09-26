package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting;


import java.io.*;

public abstract class DecryptionConfig {

    public static DecryptionConfig withKeyRingsFromFiles(final File publicKeyring,
                                                         final File secretKeyring,
                                                         boolean signatureCheckRequired, String decryptionSecretKeyPassphrase) {

        return new DecryptionConfig(signatureCheckRequired, decryptionSecretKeyPassphrase) {

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

    public static DecryptionConfig withKeyRingsFromResources(final ClassLoader classLoader, final String publicKeyring,
                                                             final String secretKeyring,
                                                             boolean signatureCheckRequired, String decryptionSecretKeyPassphrase) {

        return new DecryptionConfig(signatureCheckRequired, decryptionSecretKeyPassphrase) {


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


    private final boolean signatureCheckRequired;
    private final String decryptionSecretKeyPassphrase;

    protected DecryptionConfig(boolean signatureCheckRequired, String decryptionSecretKeyPassphrase) {
        this.signatureCheckRequired = signatureCheckRequired;
        this.decryptionSecretKeyPassphrase = decryptionSecretKeyPassphrase;
    }


    public boolean isSignatureCheckRequired() {
        return signatureCheckRequired;
    }

    public String getDecryptionSecretKeyPassphrase() {
        return decryptionSecretKeyPassphrase;
    }


    public abstract InputStream getSecretKeyRing() throws FileNotFoundException;

    public abstract InputStream getPublicKeyRing() throws IOException;
}

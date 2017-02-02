package name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting;


import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

import java.io.*;

/**
 * Bundles everything needed for decryption. Dedicated sub-classes can override.
 */
public abstract class DecryptionConfig {
    private final String decryptionSecretKeyPassphrase;

    private PGPPublicKeyRingCollection publicKeyRings;
    private PGPSecretKeyRingCollection secretKeyRings;
    private final KeyFingerPrintCalculator keyFingerPrintCalculator = new BcKeyFingerprintCalculator();

    public KeyFingerPrintCalculator getKeyFingerPrintCalculator() {
        return keyFingerPrintCalculator;
    }



    /**
     * Create a decryption config by reading keyrings from files.
     *
     * @param publicKeyring                 E.g. src/test/resources/sender.gpg.d/pubring.gpg
     * @param secretKeyring                 E.g. src/test/resources/sender.gpg.d/secring.gpg
     * @param decryptionSecretKeyPassphrase key to decrypt the secret key
     * @return the config
     */
    public static DecryptionConfig withKeyRingsFromFiles(final File publicKeyring,
                                                         final File secretKeyring,
                                                         String decryptionSecretKeyPassphrase) {

        return new DecryptionConfig(decryptionSecretKeyPassphrase) {

            final File publicKeyringFile = publicKeyring;
            final File secretKeyringFile = secretKeyring;

            @Override
            protected InputStream getPublicKeyRingStream() throws IOException {
                return new FileInputStream(publicKeyringFile);
            }

            @Override
            protected InputStream getSecretKeyRingStream() throws FileNotFoundException {
                return new FileInputStream(secretKeyringFile);
            }
        };
    }

    /**
     * Create a decryption config by reading keyrings from the classpath.
     *
     * @param classLoader                   E.g. DecryptWithOpenPGPTest.class.getClassLoader()
     * @param publicKeyring                 E.g. "recipient.gpg.d/pubring.gpg"
     * @param secretKeyring                 E.g. "recipient.gpg.d/secring.gpg"
     * @param decryptionSecretKeyPassphrase passphrase to decrypt the secret key
     * @return the config
     */
    public static DecryptionConfig withKeyRingsFromResources(final ClassLoader classLoader, final String publicKeyring,
                                                             final String secretKeyring,
                                                             String decryptionSecretKeyPassphrase) {

        return new DecryptionConfig(decryptionSecretKeyPassphrase) {


            @Override
            protected InputStream getPublicKeyRingStream() throws IOException {
                return classLoader.getResourceAsStream(publicKeyring);
            }

            @Override
            protected InputStream getSecretKeyRingStream() throws FileNotFoundException {
                return classLoader.getResourceAsStream(secretKeyring);
            }
        };
    }


    protected DecryptionConfig(String decryptionSecretKeyPassphrase) {
        this.decryptionSecretKeyPassphrase = decryptionSecretKeyPassphrase;
    }


    /**
     * @return passphrase to decrypt the secret key
     */
    public String getDecryptionSecretKeyPassphrase() {
        return decryptionSecretKeyPassphrase;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("DecryptionConfig{");
        sb.append(", decryptionSecretKeyPassphrase? :").append(decryptionSecretKeyPassphrase != null).append("\"");
        sb.append('}');
        return sb.toString();
    }

    /**
     * @return Stream that connects to  secring.gpg
     * @throws FileNotFoundException File not found
     */
    protected abstract InputStream getSecretKeyRingStream() throws IOException;

    /**
     * @return Stream that connects to  pubring.gpg
     * @throws FileNotFoundException File not found
     */
    protected abstract InputStream getPublicKeyRingStream() throws IOException;


    public PGPPublicKeyRingCollection getPublicKeyRings() throws IOException, PGPException {

        if (publicKeyRings == null) {
            publicKeyRings = new

                    PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(getPublicKeyRingStream()), keyFingerPrintCalculator);

        }
        return publicKeyRings;
    }

    public PGPSecretKeyRingCollection getSecretKeyRings() throws IOException, PGPException {
        if (secretKeyRings == null) {
            secretKeyRings = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(getSecretKeyRingStream()), keyFingerPrintCalculator);
        }
        return secretKeyRings;
    }

}

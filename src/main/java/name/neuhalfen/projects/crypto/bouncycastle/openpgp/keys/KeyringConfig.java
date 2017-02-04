package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys;


import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

import javax.annotation.Nullable;
import java.io.*;


public abstract class KeyringConfig {

    private final KeyringConfigCallback callback;
    private PGPPublicKeyRingCollection publicKeyRings;
    private PGPSecretKeyRingCollection secretKeyRings;
    private final KeyFingerPrintCalculator keyFingerPrintCalculator = new BcKeyFingerprintCalculator();

    protected KeyringConfig(KeyringConfigCallback callback) {
        this.callback = callback;
    }

    /**
     * Create a decryption config by reading keyrings from files.
     *
     * @param publicKeyring E.g. src/test/resources/sender.gpg.d/pubring.gpg
     * @param secretKeyring E.g. src/test/resources/sender.gpg.d/secring.gpg
     * @return the config
     */
    public static KeyringConfig withKeyRingsFromFiles(final File publicKeyring,
                                                      final File secretKeyring,
                                                      KeyringConfigCallback callback) {

        return new KeyringConfig(callback) {
            @Override
            protected InputStream getPublicKeyRingStream() throws IOException {
                return new FileInputStream(publicKeyring);
            }

            @Override
            protected InputStream getSecretKeyRingStream() throws FileNotFoundException {
                return new FileInputStream(secretKeyring);
            }
        };
    }

    /**
     * Create a decryption config by reading keyrings from the classpath.
     *
     * @param classLoader       E.g. DecryptWithOpenPGPTest.class.getClassLoader()
     * @param publicKeyringPath E.g. "recipient.gpg.d/pubring.gpg"
     * @param secretKeyringPath E.g. "recipient.gpg.d/secring.gpg"
     * @return the config
     */
    public static KeyringConfig withKeyRingsFromResources(final ClassLoader classLoader,
                                                          final String publicKeyringPath,
                                                          final String secretKeyringPath,
                                                          KeyringConfigCallback callback) {

        return new KeyringConfig(callback) {


            @Override
            protected InputStream getPublicKeyRingStream() throws IOException {
                return classLoader.getResourceAsStream(publicKeyringPath);
            }

            @Override
            protected InputStream getSecretKeyRingStream() throws FileNotFoundException {
                return classLoader.getResourceAsStream(secretKeyringPath);
            }
        };
    }


    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("KeyringConfig{");
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

    public
    @Nullable
    char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyID) {
        if (callback != null) {
            return callback.decryptionSecretKeyPassphraseForSecretKeyId(keyID);
        } else {
            return null;
        }
    }
}

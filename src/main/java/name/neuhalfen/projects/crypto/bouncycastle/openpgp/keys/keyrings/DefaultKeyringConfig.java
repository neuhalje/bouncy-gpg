package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.KeyringConfigCallback;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

import javax.annotation.Nullable;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;


public abstract class DefaultKeyringConfig implements KeyringConfig {

    private final KeyringConfigCallback callback;
    private PGPPublicKeyRingCollection publicKeyRings;
    private PGPSecretKeyRingCollection secretKeyRings;
    private final KeyFingerPrintCalculator keyFingerPrintCalculator = new BcKeyFingerprintCalculator();

    DefaultKeyringConfig(KeyringConfigCallback callback) {
        this.callback = callback;
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


    @Override
    public PGPPublicKeyRingCollection getPublicKeyRings() throws IOException, PGPException {

        if (publicKeyRings == null) {
            publicKeyRings = new

                    PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(getPublicKeyRingStream()), keyFingerPrintCalculator);

        }
        return publicKeyRings;
    }

    @Override
    public PGPSecretKeyRingCollection getSecretKeyRings() throws IOException, PGPException {
        if (secretKeyRings == null) {
            secretKeyRings = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(getSecretKeyRingStream()), keyFingerPrintCalculator);
        }
        return secretKeyRings;
    }

    @Override
    public
    @Nullable
    char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyID) {
        if (callback != null) {
            return callback.decryptionSecretKeyPassphraseForSecretKeyId(keyID);
        } else {
            return null;
        }
    }

    @Override
    public KeyFingerPrintCalculator getKeyFingerPrintCalculator() {
        return keyFingerPrintCalculator;
    }

}

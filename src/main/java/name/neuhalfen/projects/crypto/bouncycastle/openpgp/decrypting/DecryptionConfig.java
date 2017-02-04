package name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

import java.io.IOException;

/**
 * Bundles everything needed for decryption. Dedicated sub-classes can override.
 */
public class DecryptionConfig {
    private final KeyringConfig keyringConfig;


    private final KeyFingerPrintCalculator keyFingerPrintCalculator;

    public KeyFingerPrintCalculator getKeyFingerPrintCalculator() {
        return keyFingerPrintCalculator;
    }


    public DecryptionConfig(KeyringConfig keyringConfig) {
        this.keyringConfig = keyringConfig;
        keyFingerPrintCalculator = new BcKeyFingerprintCalculator();
    }


    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("DecryptionConfig{");
        sb.append(", keyringConfig :").append(keyringConfig.toString()).append('}');
        return sb.toString();
    }


    public PGPPublicKeyRingCollection getPublicKeyRings() throws IOException, PGPException {

        return keyringConfig.getPublicKeyRings();
    }

    public PGPSecretKeyRingCollection getSecretKeyRings() throws IOException, PGPException {

        return keyringConfig.getSecretKeyRings();
    }

    public char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyID) {
        return keyringConfig.decryptionSecretKeyPassphraseForSecretKeyId(keyID);
    }
}

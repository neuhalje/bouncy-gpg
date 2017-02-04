package name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;

import java.io.IOException;

/**
 * Bundles everything needed for decryption. Dedicated sub-classes can override.
 */
public interface DecryptionConfig {
    KeyFingerPrintCalculator getKeyFingerPrintCalculator();

    PGPPublicKeyRingCollection getPublicKeyRings() throws IOException, PGPException;

    PGPSecretKeyRingCollection getSecretKeyRings() throws IOException, PGPException;

    char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyID);
}

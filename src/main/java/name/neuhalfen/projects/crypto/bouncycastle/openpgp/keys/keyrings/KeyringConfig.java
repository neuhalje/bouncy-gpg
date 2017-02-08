package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;

import javax.annotation.Nullable;
import java.io.IOException;

/**
 * Interface that describes keyrings (e.g. pubring.gpg ans secring.gpg)
 *
 * @see KeyringConfigs
 */
public interface KeyringConfig {
    PGPPublicKeyRingCollection getPublicKeyRings() throws IOException, PGPException;

    PGPSecretKeyRingCollection getSecretKeyRings() throws IOException, PGPException;

    @Nullable
    char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyID);

    KeyFingerPrintCalculator getKeyFingerPrintCalculator();
}

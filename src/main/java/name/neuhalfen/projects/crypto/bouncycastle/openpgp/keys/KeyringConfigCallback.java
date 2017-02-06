package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys;

import javax.annotation.Nullable;

// FIXME
public interface KeyringConfigCallback {
    @Nullable
    char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyID);
}

package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys;

// FIXME
public interface KeyringConfigCallback {
    char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyID);
}

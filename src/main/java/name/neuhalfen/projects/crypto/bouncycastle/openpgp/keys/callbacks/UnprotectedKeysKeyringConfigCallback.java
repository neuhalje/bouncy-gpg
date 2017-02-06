package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.KeyringConfigCallback;

public class UnprotectedKeysKeyringConfigCallback implements KeyringConfigCallback {
    @Override
    public char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyID) {
        return null;
    }
}

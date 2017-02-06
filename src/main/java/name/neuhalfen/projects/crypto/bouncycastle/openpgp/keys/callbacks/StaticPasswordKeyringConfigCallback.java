package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.KeyringConfigCallback;

public class StaticPasswordKeyringConfigCallback implements KeyringConfigCallback {


    private final char[] passphrase;

    public StaticPasswordKeyringConfigCallback(char[] passphrase) {
        this.passphrase = passphrase;
    }

    @Override
    public char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyID) {
        return passphrase;
    }
}

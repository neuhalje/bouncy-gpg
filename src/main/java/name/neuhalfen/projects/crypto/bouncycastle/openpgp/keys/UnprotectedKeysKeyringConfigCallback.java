package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys;


class UnprotectedKeysKeyringConfigCallback implements KeyringConfigCallback {
    @Override
    public char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyID) {
        return null;
    }
}

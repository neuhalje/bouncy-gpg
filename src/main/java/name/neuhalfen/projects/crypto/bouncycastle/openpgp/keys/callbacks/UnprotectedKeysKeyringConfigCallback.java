package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;


final class UnprotectedKeysKeyringConfigCallback implements KeyringConfigCallback {

  UnprotectedKeysKeyringConfigCallback() {
    // Nothing to do
  }

  @SuppressWarnings("PMD.ReturnEmptyArrayRatherThanNull")
  @Override
  public char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyId) {
    return null;
  }
}

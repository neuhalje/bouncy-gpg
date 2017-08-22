package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;


import org.bouncycastle.util.Arrays;

final class StaticPasswordKeyringConfigCallback implements KeyringConfigCallback {


  private final char[] passphrase;

  public StaticPasswordKeyringConfigCallback(char[] passphrase) {
    this.passphrase = Arrays.clone(passphrase);
  }

  @Override
  public char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyID) {
    return  Arrays.clone(passphrase);
  }
}

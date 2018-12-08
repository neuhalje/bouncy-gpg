package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;


import static java.util.Objects.requireNonNull;

import org.bouncycastle.util.Arrays;

final class StaticPasswordKeyringConfigCallback implements KeyringConfigCallback {


  private final char[] passphrase;

  @SuppressWarnings("PMD.UseVarargs")
  public StaticPasswordKeyringConfigCallback(char[] passphrase) {
    requireNonNull(passphrase, "passphrase must not be null");
    this.passphrase = Arrays.clone(passphrase);
  }

  @SuppressWarnings("PMD.UseVarargs")
  @Override
  public char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyId) {
    return Arrays.clone(passphrase);
  }
}

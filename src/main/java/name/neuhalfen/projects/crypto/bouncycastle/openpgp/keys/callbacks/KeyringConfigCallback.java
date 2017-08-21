package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

import javax.annotation.Nullable;

/**
 * Strategy to provide passwords for secret keys.
 */
public interface KeyringConfigCallback {

  /**
   * The keyid passed in is the keyid of the sub-key used. E.g. for the following keyring you'd
   * expect keyID values of 0x86DAC13816FE6FE2 or 0x54A3DB374F787AB7 . ./sender.gpg.d/pubring.gpg
   * -------------------------- pub   2048R/0xAFF0658D23FB56E6 2015-09-27 uid [ultimate] Sven Sender
   * (Password: sender) &lt;sender@example.com&gt; sub 2048R/0x86DAC13816FE6FE2 2015-09-27 . pub
   * 2048R/0x3DF16BD7C3F280F3 2015-09-27 uid [ultimate] Rezi Recipient (Password: recipient)
   * &lt;recipient@example.com&gt; sub 2048R/0x54A3DB374F787AB7 2015-09-27
   *
   * @param keyID The password for this key is needed
   * @return the passphrase OR null (if unknown/no passphrase)
   */
  @SuppressWarnings("PMD.UseVarargs")
  @Nullable
  char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyID);
}

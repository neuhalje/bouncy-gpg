package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings;

import java.io.IOException;
import javax.annotation.Nullable;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;

/**
 * Interface that describes keyrings (e.g. pubring.gpg and secring.gpg, or any other means to get a
 * list of valid keys). . Custom implementations might for example get the keys from a webservice.
 *
 * @see KeyringConfigs
 */
public interface KeyringConfig {

  PGPPublicKeyRingCollection getPublicKeyRings() throws IOException, PGPException;

  PGPSecretKeyRingCollection getSecretKeyRings() throws IOException, PGPException;

  /**
   * The keyid passed in is the keyid of the sub-key used. E.g. for the following keyring you'd
   * expect keyID values of 0x86DAC13816FE6FE2 or 0x54A3DB374F787AB7 . ./sender.gpg.d/pubring.gpg
   * -------------------------- pub   2048R/0xAFF0658D23FB56E6 2015-09-27 uid [ultimate] Sven Sender
   * (Password: sender) &lt;sender@example.com&gt; sub 2048R/0x86DAC13816FE6FE2 2015-09-27 . pub
   * 2048R/0x3DF16BD7C3F280F3 2015-09-27 uid [ultimate] Rezi Recipient (Password: recipient)
   * &lt;recipient@example.com&gt; sub 2048R/0x54A3DB374F787AB7 2015-09-27 . Most implementations
   * delegate to an implementation of {@link name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback}
   *
   * @param keyID The password for this key is needed
   * @return the passphrase OR null (if unknown/no passphrase)
   */
  @Nullable
  char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyID);

  /**
   * E.g. cache a 'new BcKeyFingerprintCalculator()'
   *
   * @return calculator
   */
  KeyFingerPrintCalculator getKeyFingerPrintCalculator();
}

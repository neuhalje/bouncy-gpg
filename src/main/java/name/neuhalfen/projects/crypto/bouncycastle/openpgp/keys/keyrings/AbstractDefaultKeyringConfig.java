package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings;


import static java.util.Objects.requireNonNull;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;


abstract class AbstractDefaultKeyringConfig implements KeyringConfig {

  @Nonnull
  private final KeyringConfigCallback callback;
  private final KeyFingerPrintCalculator keyFingerPrintCalculator = new BcKeyFingerprintCalculator();
  private PGPPublicKeyRingCollection publicKeyRings;
  private PGPSecretKeyRingCollection secretKeyRings;

  AbstractDefaultKeyringConfig(final KeyringConfigCallback callback) {
    requireNonNull(callback, "callback must not be null");

    this.callback = callback;
  }


  @SuppressWarnings("PMD.ShortVariable")
  @Override
  public String toString() {
    return new StringBuilder("AbstractDefaultKeyringConfig{")
        .append("callback=").append(callback)
        .append(", keyFingerPrintCalculator=").append(keyFingerPrintCalculator)
        .append(", publicKeyRings=").append(publicKeyRings)
        .append(", secretKeyRings=").append(secretKeyRings == null ? "null" : "<present>")
        .append('}').toString();
  }

  /**
   * @return Stream that connects to  secring.gpg
   *
   * @throws FileNotFoundException File not found
   */
  protected abstract InputStream getSecretKeyRingStream() throws IOException;

  /**
   * @return Stream that connects to  pubring.gpg
   *
   * @throws FileNotFoundException File not found
   */
  protected abstract InputStream getPublicKeyRingStream() throws IOException;


  @Override
  public PGPPublicKeyRingCollection getPublicKeyRings() throws IOException, PGPException {

    if (publicKeyRings == null) {
      publicKeyRings = new
          PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(getPublicKeyRingStream()),
          keyFingerPrintCalculator);

    }
    return publicKeyRings;
  }

  @Override
  public PGPSecretKeyRingCollection getSecretKeyRings() throws IOException, PGPException {
    if (secretKeyRings == null) {
      secretKeyRings = new PGPSecretKeyRingCollection(
          PGPUtil.getDecoderStream(getSecretKeyRingStream()), keyFingerPrintCalculator);
    }
    return secretKeyRings;
  }

  @Override
  public
  @Nullable
  char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyID) {
    return callback.decryptionSecretKeyPassphraseForSecretKeyId(keyID);
  }

  @Override
  public KeyFingerPrintCalculator getKeyFingerPrintCalculator() {
    return keyFingerPrintCalculator;
  }

}

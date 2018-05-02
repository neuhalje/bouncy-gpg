package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings;


import static java.util.Collections.EMPTY_LIST;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

public final class InMemoryKeyring implements KeyringConfig {

  @Nonnull
  private final KeyringConfigCallback callback;
  private final KeyFingerPrintCalculator keyFingerPrintCalculator = new BcKeyFingerprintCalculator();
  @Nonnull
  private PGPPublicKeyRingCollection publicKeyRings;
  @Nonnull
  private PGPSecretKeyRingCollection secretKeyRings;

  @SuppressWarnings("unchecked")
  InMemoryKeyring(final KeyringConfigCallback callback) throws IOException, PGPException {
    if (callback == null) {
      throw new IllegalArgumentException("callback must not be null");
    }
    this.callback = callback;
    //noinspection unchecked
    this.publicKeyRings = new PGPPublicKeyRingCollection(EMPTY_LIST);
    this.secretKeyRings = new PGPSecretKeyRingCollection(EMPTY_LIST);
  }

  /**
   * Add a new public keyring to the public keyrings. . Can read the result of "gpg --export" and
   * "gpg --export -a keyid" . E.g.  "gpg --export -a keyid": addPublicKey("-----BEGIN PGP PUBLIC
   * KEY BLOCK----- ....".getBytes("US-ASCII")
   *
   * @param encodedPublicKey the key ascii armored or binary
   * @throws IOException IO is dangerous
   * @throws PGPException E.g. this is nor a valid key
   */
  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.UseVarargs"})
  public void addPublicKey(byte[] encodedPublicKey) throws IOException, PGPException {

    if (encodedPublicKey == null) {
      throw new IllegalArgumentException("encodedPublicKey must not be null");
    }

    InputStream raw = null;
    InputStream decoded = null;
    try {
      raw = new ByteArrayInputStream(encodedPublicKey);
      decoded = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(raw);
      PGPPublicKeyRing pgpPub = new PGPPublicKeyRing(decoded, getKeyFingerPrintCalculator());
      this.publicKeyRings = PGPPublicKeyRingCollection
              .addPublicKeyRing(this.publicKeyRings, pgpPub);
    }
    catch (Exception e) {
      if (decoded != null) {
        decoded.close();
      }
      if (raw != null) {
        raw.close();
      }
      throw e;
    }
  }


  /**
   * Add a new secret keyring to the public keyrings. . Can read the result of "gpg --export" and
   * "gpg --export -a keyid" . E.g. "gpg --export-secret-key -a keyid": addSecretKey("-----BEGIN PGP
   * PRIVATE KEY BLOCK----- ....".getBytes("US-ASCII") <p> The password is queried via the callback
   * (decryptionSecretKeyPassphraseForSecretKeyId).
   *
   * @param encodedPrivateKey the key ascii armored or binary
   * @throws IOException IO is dangerous
   * @throws PGPException E.g. this is nor a valid key
   */
  @SuppressWarnings("PMD.LawOfDemeter")
  public void addSecretKey(byte[] encodedPrivateKey) throws IOException, PGPException {

    if (encodedPrivateKey == null) {
      throw new IllegalArgumentException("encodedPrivateKey must not be null");
    }

    InputStream raw = null;
    InputStream decoded = null;
    try {
      raw = new ByteArrayInputStream(encodedPrivateKey);
      decoded = org.bouncycastle.openpgp.PGPUtil
              .getDecoderStream(raw);
      PGPSecretKeyRing pgpPRivate = new PGPSecretKeyRing(decoded, getKeyFingerPrintCalculator());
      this.secretKeyRings =
              PGPSecretKeyRingCollection
                      .addSecretKeyRing(this.secretKeyRings, pgpPRivate);
    } catch (Exception e) {
      if (decoded != null) {
        decoded.close();
      }
      if (raw != null) {
        raw.close();
      }
      throw e;
    }
  }

  @Nonnull
  @Override
  public PGPPublicKeyRingCollection getPublicKeyRings() throws IOException, PGPException {
    return this.publicKeyRings;
  }

  @Nonnull
  @Override
  public PGPSecretKeyRingCollection getSecretKeyRings() throws IOException, PGPException {
    return this.secretKeyRings;
  }

  @Nullable
  @Override
  public char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyID) {
    return callback.decryptionSecretKeyPassphraseForSecretKeyId(keyID);
  }

  @Override
  public KeyFingerPrintCalculator getKeyFingerPrintCalculator() {
    return keyFingerPrintCalculator;
  }
}

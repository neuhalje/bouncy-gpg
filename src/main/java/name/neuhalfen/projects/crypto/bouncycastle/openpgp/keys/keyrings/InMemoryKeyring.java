package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings;


import static java.util.Collections.EMPTY_LIST;
import static java.util.Objects.requireNonNull;

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
    requireNonNull(callback, "callback must not be null");

    this.callback = callback;
    //noinspection unchecked
    this.publicKeyRings = new PGPPublicKeyRingCollection(EMPTY_LIST);
    this.secretKeyRings = new PGPSecretKeyRingCollection(EMPTY_LIST);
  }

  /**
   * <p>Add a new public keyring to the public keyrings. . Can read the result of {@code gpg
   * --export} and
   * {@code gpg --export -a keyid}.</p>
   *
   * <p>
   * E.g. for "{@code gpg --export -a keyid}":
   *
   * <pre><code>
   * addPublicKey(
   * "-----BEGIN PGP PUBLIC KEY BLOCK----- ...."
   * .getBytes("US-ASCII");
   * </code></pre>
   * </p>
   *
   * @param encodedPublicKey the public key
   *
   * @throws IOException IO is dangerous
   * @throws PGPException E.g. this is nor a valid key
   */
  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.UseVarargs"})
  public void addPublicKey(byte[] encodedPublicKey) throws IOException, PGPException {
    requireNonNull(encodedPublicKey, "encodedPublicKey must not be null");

    try (
        InputStream raw = new ByteArrayInputStream(encodedPublicKey);
        InputStream decoded = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(raw)
    ) {
      final PGPPublicKeyRing pgpPub = new PGPPublicKeyRing(decoded, getKeyFingerPrintCalculator());

      addPublicKeyRing(pgpPub);
    }
  }


  /**
   * <p>Add a new secret keyring to the secret keyrings.</p>
   * <p>
   * Can read the result of "{@code gpg --export}" and
   * 2{@code gpg --export -a keyid}".</p>
   *
   * <p>E.g. "{@code gpg --export-secret-key -a keyid}":
   * <pre><code>
   * addSecretKey("-----BEGIN PGP PRIVATE KEY BLOCK----- ...."
   * .getBytes("US-ASCII")
   * </code></pre>
   * </p>
   * <p> The password is queried via the callback
   * (decryptionSecretKeyPassphraseForSecretKeyId).
   *
   * </p>
   *
   * @param encodedPrivateKey the key, either ascii armored or binary
   *
   * @throws IOException IO is dangerous
   * @throws PGPException E.g. this is nor a valid key
   */
  @SuppressWarnings("PMD.LawOfDemeter")
  public void addSecretKey(byte[] encodedPrivateKey) throws IOException, PGPException {
    requireNonNull(encodedPrivateKey, "encodedPrivateKey must not be null");

    try (
        InputStream raw = new ByteArrayInputStream(encodedPrivateKey);
        InputStream decoded = org.bouncycastle.openpgp.PGPUtil
            .getDecoderStream(raw)
    ) {
      final PGPSecretKeyRing pgpPRivate = new PGPSecretKeyRing(decoded,
          getKeyFingerPrintCalculator());
      addSecretKeyRing(pgpPRivate);
    }
  }


  /**
   * <p>Add a new secret keyring to the secret keyrings.</p>
   *
   * @param keyring the keyring
   */
  @SuppressWarnings("PMD.LawOfDemeter")
  public void addSecretKeyRing(PGPSecretKeyRing keyring) {
    requireNonNull(keyring, "keyring must not be null");

    this.secretKeyRings =
        PGPSecretKeyRingCollection
            .addSecretKeyRing(this.secretKeyRings, keyring);
  }


  /**
   * <p>Add a new secret keyring to the secret keyrings.</p>
   *
   * @param keyring the keyring
   */
  @SuppressWarnings("PMD.LawOfDemeter")
  public void addPublicKeyRing(PGPPublicKeyRing keyring) {
    requireNonNull(keyring, "keyring must not be null");

    this.publicKeyRings =
        PGPPublicKeyRingCollection
            .addPublicKeyRing(this.publicKeyRings, keyring);
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

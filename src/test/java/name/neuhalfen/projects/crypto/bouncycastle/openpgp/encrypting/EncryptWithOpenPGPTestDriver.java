package name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPAlgorithmSuite;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.PGPUtilities;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.util.io.Streams;

/**
 * TODO: This class now only acts as a test-driver and should be factored into oblivion
 */
final class EncryptWithOpenPGPTestDriver {

  /**
   * The Constant LOGGER.
   */
  private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
      .getLogger(EncryptWithOpenPGPTestDriver.class);


  /**
   * Milliseconds per second.
   */
  private static final int MLLIES_PER_SEC = 1000;

  private final KeyringConfig config;

  private final PGPAlgorithmSuite algorithmSuite;

  /**
   * The signature uid.
   */
  private final String signatureUid;

  /**
   * The encryption public key ring.
   */
  private final PGPPublicKeyRing encryptionPublicKeyRing;


  public EncryptWithOpenPGPTestDriver(final EncryptionConfig config,
      final PGPAlgorithmSuite algorithmSuite) throws IOException {

    try {

      this.signatureUid = config.getSignatureSecretKeyId();

      this.encryptionPublicKeyRing =
          PGPUtilities.extractPublicKeyRingForUserId(config.getEncryptionPublicKeyId(),
              config.getPublicKeyRings());

    } catch (PGPException e) {
      throw new RuntimeException("Failed to construct EncryptWithOpenPGPTestDriver", e);
    }
    this.config = config.getConfig();
    this.algorithmSuite = algorithmSuite;
  }


  public void encryptAndSign(final InputStream is, final OutputStream os) throws IOException,
      NoSuchAlgorithmException, SignatureException, PGPException, NoSuchProviderException {
    final long starttime = System.currentTimeMillis();

    final PGPPublicKey encryptionKey = PGPUtilities.getEncryptionKey(this.encryptionPublicKeyRing);
    if (encryptionKey == null) {
      throw new PGPException("Could not find a valid encryption key for uid ");
    }
    encryptAndSign(is, os, encryptionKey, true);

    LOGGER.debug("Encrypt and sign duration {}s",
        (System.currentTimeMillis() - starttime) / MLLIES_PER_SEC);
  }


  /**
   * Method to sign-and-encrypt.
   *
   * @param in the in
   * @param out the out
   * @param pubEncKey the pub enc key
   * @param armor if OutputStream should be "armored", that means base64 encoded
   * @throws IOException Signals that an I/O exception has occurred.
   * @throws NoSuchAlgorithmException the no such algorithm exception
   * @throws NoSuchProviderException the no such provider exception
   * @throws PGPException the pGP exception
   * @throws SignatureException the signature exception {@link org.bouncycastle.bcpg.HashAlgorithmTags}
   * {@link org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags}
   */
  private void encryptAndSign(final InputStream in, OutputStream out, final PGPPublicKey pubEncKey,
      final boolean armor) throws IOException,
      NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException {

    try (final OutputStream encryptionStream = PGPEncryptingStream
        .create(config, algorithmSuite, signatureUid, out, armor, pubEncKey)) {
      Streams.pipeAll(in, encryptionStream);
      encryptionStream.flush();
    }
    out.flush();
  }
}
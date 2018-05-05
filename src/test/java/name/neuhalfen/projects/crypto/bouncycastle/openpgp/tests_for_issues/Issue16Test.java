package name.neuhalfen.projects.crypto.bouncycastle.openpgp.tests_for_issues;


import static org.junit.Assert.assertEquals;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.time.Instant;
import java.util.Date;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.RFC4880TestKeyringsDedicatedSigningKey;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.RFC4880TestKeyringsMasterKeyAsSigningKey;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

public class Issue16Test {


  @Before
  public void installBCProvider() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }


  @Test
  @Ignore("This only helps in manual investigation")
  public void forManualAnalysis__with_keysFromGPG_files()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {

    final KeyringConfig config = KeyringConfigs
        .withKeyRingsFromFiles(new File("path/to/pubring.gpg"), new File("/path/to/secring.gpg"),
            KeyringConfigCallbacks.withPassword("s3cret"));

    final String recipient = "recipient@example.com";
    final String signer = "signer@example.com";

    encryptToStdout(config,
       recipient,
        signer,
        new Date());
  }


  @Test
  @Ignore("This only helps in manual investigation")
  public void forManualAnalysis__with_dedicatedSigningKey_encryptToStdout()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {

    encryptToStdout(RFC4880TestKeyringsDedicatedSigningKey.publicAndPrivateKeyKeyringConfig(),
        RFC4880TestKeyringsDedicatedSigningKey.UID_EMAIL,
        RFC4880TestKeyringsDedicatedSigningKey.UID_EMAIL,
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_GUARANTEED_EXPIRED_AT);
  }

  @Test
  @Ignore("This only helps in manual investigation")
  public void forManualAnalysis__with_masterKeyAsSigningKey_encryptToStdout()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {

    encryptToStdout(RFC4880TestKeyringsMasterKeyAsSigningKey.publicAndPrivateKeyKeyringConfig(),
        RFC4880TestKeyringsMasterKeyAsSigningKey.UID_EMAIL,
        RFC4880TestKeyringsMasterKeyAsSigningKey.UID_EMAIL,
        new Date(Long.MAX_VALUE));
  }

  void encryptToStdout(final KeyringConfig config, final String recipientUid,
      final String signingUid,
      final Date dateOfTimestampVerification)
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    final byte[] expectedPlaintext = ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes("US-ASCII");

    byte[] bytes;
    try (
        final ByteArrayInputStream is = new ByteArrayInputStream(expectedPlaintext);
        final ByteArrayOutputStream byteOutput = new ByteArrayOutputStream();

        final OutputStream outputStream = BouncyGPG
            .encryptToStream()
            .withConfig(config)
            .setReferenceDateForKeyValidityTo(dateOfTimestampVerification)
            .withStrongAlgorithms()
            .toRecipient(recipientUid)
            .andSignWith(signingUid)
            .armorAsciiOutput()
            .andWriteTo(byteOutput)
    ) {
      Streams.pipeAll(is, outputStream);

      outputStream.close();
      bytes = byteOutput.toByteArray();
    }

    final String ciphertext = new String(bytes, "US-ASCII");
    System.out.println(
        "Key expiration check for " + dateOfTimestampVerification.toString() + ", encrypted to '"
            + recipientUid + "', and signed by '" + signingUid
            + "'\n\n\necho '"
            + ciphertext + "'| gpg -v -d");
  }

  @Test
  public void issue16_validateCorrectSigningKey_skipExpired()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    signAtDateAndValidateExpectedKey(
        RFC4880TestKeyringsDedicatedSigningKey.publicAndPrivateKeyKeyringConfig(),
        RFC4880TestKeyringsDedicatedSigningKey.UID_EMAIL,
        RFC4880TestKeyringsDedicatedSigningKey.UID_EMAIL,
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_GUARANTEED_EXPIRED_AT,
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_ACTIVE);
  }

  @Test
  public void issue16_validateCorrectSigningKey_useLastValidKey()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    signAtDateAndValidateExpectedKey(
        RFC4880TestKeyringsDedicatedSigningKey.publicAndPrivateKeyKeyringConfig(),
        RFC4880TestKeyringsDedicatedSigningKey.UID_EMAIL,
        RFC4880TestKeyringsDedicatedSigningKey.UID_EMAIL,
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_GUARANTEED_VALID_AT,
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_EXPIRED);
  }


  @Test
  public void issue16_validateCorrectSigningKey_whenMasterKeyIsSigningKey()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    signAtDateAndValidateExpectedKey(
        RFC4880TestKeyringsMasterKeyAsSigningKey.publicAndPrivateKeyKeyringConfig(),
        RFC4880TestKeyringsMasterKeyAsSigningKey.UID_EMAIL,
        RFC4880TestKeyringsMasterKeyAsSigningKey.UID_EMAIL,
        new Date(Long.MAX_VALUE),
        RFC4880TestKeyringsMasterKeyAsSigningKey.MASTER_KEY_ID);
  }


  private void signAtDateAndValidateExpectedKey(final KeyringConfig config,
      final String recipientUid,
      final String signingUid, final Date dateOfTimestampVerification,
      long expectedSignatureKey)
      throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
    final byte[] expectedPlaintext = ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes("US-ASCII");

    byte[] bytes;
    try (
        final ByteArrayInputStream is = new ByteArrayInputStream(expectedPlaintext);
        final ByteArrayOutputStream byteOutput = new ByteArrayOutputStream();

        final OutputStream outputStream = BouncyGPG
            .encryptToStream()
            .withConfig(config)
            .setReferenceDateForKeyValidityTo(dateOfTimestampVerification)
            .withStrongAlgorithms()
            .toRecipient(recipientUid)
            .andSignWith(signingUid)
            .armorAsciiOutput()
            .andWriteTo(byteOutput)
    ) {
      Streams.pipeAll(is, outputStream);

      outputStream.close();
      bytes = byteOutput.toByteArray();
    }

    ByteArrayOutputStream output = new ByteArrayOutputStream();

    try (
        final ByteArrayInputStream cipherTextStream = new ByteArrayInputStream(bytes);

        final BufferedOutputStream bufferedOut = new BufferedOutputStream(output);

        // test that the active key is used
        final InputStream plaintextStream = BouncyGPG
            .decryptAndVerifyStream()
            .withConfig(config)
            .setReferenceDateForKeyValidityTo(dateOfTimestampVerification)
            .andRequireSignatureFromAllKeys(expectedSignatureKey)
            .fromEncryptedInputStream(cipherTextStream)

    ) {
      Streams.pipeAll(plaintextStream, bufferedOut);
    }

    assertEquals(ExampleMessages.IMPORTANT_QUOTE_TEXT, output.toString("US-ASCII"));
  }


}

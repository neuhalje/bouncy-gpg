package name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages.IMPORTANT_QUOTE_NOT_ENCRYPTED_TO_ME;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages.IMPORTANT_QUOTE_NOT_SIGNED_NOT_COMPRESSED;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages.IMPORTANT_QUOTE_SIGNED_BY_2_KNOWN_1_UNKNOWN_KEY;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages.IMPORTANT_QUOTE_SIGNED_COMPRESSED;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages.IMPORTANT_QUOTE_SIGNED_MULTIPLE_COMPRESSED;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages.IMPORTANT_QUOTE_SIGNED_MULTIPLE_V2_COMPRESSED;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages.IMPORTANT_QUOTE_SIGNED_NOT_COMPRESSED;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages.IMPORTANT_QUOTE_SIGNED_UNKNOWN_KEY_COMPRESSED;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages.IMPORTANT_QUOTE_TEXT;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationStrategies;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationStrategy;
import org.bouncycastle.util.io.Streams;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class DecryptionStreamFactoryTest {

  @Before
  public void installBCProvider() {
    BouncyGPG.registerProvider();
  }


  private String decrypt(byte[] encrypted, KeyringConfig config,
      SignatureValidationStrategy signatureValidationStrategy) throws IOException {
    final DecryptionStreamFactory sut = DecryptionStreamFactory
        .create(config, signatureValidationStrategy);

    final InputStream plainTextInputStream;
    try {
      plainTextInputStream = sut.wrapWithDecryptAndVerify(new ByteArrayInputStream(encrypted));
    } catch (NoSuchProviderException e) {
      assertTrue("BC provider must be registered by test", false);
      throw new AssertionError(e);
    }

    ByteArrayOutputStream res = new ByteArrayOutputStream();
    Streams.pipeAll(plainTextInputStream, res);
    res.close();
    plainTextInputStream.close();

    String decrypted = res.toString("US-ASCII");
    return decrypted;
  }

  @Test
  public void decrypting_anyData_doesNotCloseInputStream()
      throws IOException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {

    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();
    final DecryptionStreamFactory sut = DecryptionStreamFactory
        .create(config, SignatureValidationStrategies.ignoreSignatures());

    InputStream in = spy(
        new ByteArrayInputStream(IMPORTANT_QUOTE_SIGNED_COMPRESSED.getBytes(
            "US-ASCII")));

    final InputStream decryptAndVerify = sut.wrapWithDecryptAndVerify(in);
    decryptAndVerify.close();

    verify(in, never()).close();
  }


  @Test
  public void decryptingAndVerifying_smallAmountsOfData_correctlyDecryptsUncompressedAndArmored()
      throws IOException, SignatureException, NoSuchAlgorithmException {
    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    String decryptedQuote = decrypt(IMPORTANT_QUOTE_SIGNED_NOT_COMPRESSED.getBytes(
        "US-ASCII"),
        config, SignatureValidationStrategies.ignoreSignatures());
    Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
  }

  @Test
  public void decryptingAndVerifyingMessageWith_Single_Signature_requiringAnySignature_correctlyDecryptsCompressedAndArmored()
      throws IOException, SignatureException, NoSuchAlgorithmException {

    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    String decryptedQuote = decrypt(IMPORTANT_QUOTE_SIGNED_COMPRESSED.getBytes(
        "US-ASCII"), config,
        SignatureValidationStrategies.requireAnySignature());
    Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
  }

  @Test
  public void decryptingAndVerifyingMessageWith_unknownSignature_requiringNoSignature_correctlyDecryptsCompressedAndArmored()
      throws IOException, SignatureException, NoSuchAlgorithmException {

    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    String decryptedQuote = decrypt(
        IMPORTANT_QUOTE_SIGNED_UNKNOWN_KEY_COMPRESSED.getBytes("US-ASCII"), config,
        SignatureValidationStrategies.ignoreSignatures());
    Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
  }


  @Test(expected = IOException.class)
  public void decryptingAndVerifyingMessageWith_noSignature_requiringAnySignature_fails()
      throws IOException, SignatureException, NoSuchAlgorithmException {

    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    decrypt(IMPORTANT_QUOTE_NOT_SIGNED_NOT_COMPRESSED.getBytes("US-ASCII"), config,
        SignatureValidationStrategies.requireAnySignature());
  }

  @Test(expected = IOException.class)
  public void decryptingAndVerifyingMessageWith_unknownSignature_requiringAnySignature_fails()
      throws IOException, SignatureException, NoSuchAlgorithmException {

    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    decrypt(IMPORTANT_QUOTE_SIGNED_UNKNOWN_KEY_COMPRESSED.getBytes("US-ASCII"), config,
        SignatureValidationStrategies.requireAnySignature());
  }

  @Test
  public void decryptingAndVerifyingMessageWith_Multiple_Signatures_requiringNoSignature_correctlyDecryptsCompressedAndArmored()
      throws IOException, SignatureException, NoSuchAlgorithmException {
    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    final String decryptedQuote = decrypt(
        IMPORTANT_QUOTE_SIGNED_MULTIPLE_COMPRESSED.getBytes("US-ASCII"), config,
        SignatureValidationStrategies.ignoreSignatures());

    Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
  }

  @Test(expected = IOException.class)
  public void decryptingTamperedSignedCiphertext_fails()
      throws IOException, NoSuchAlgorithmException, NoSuchProviderException {

    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();
    final DecryptionStreamFactory sut = DecryptionStreamFactory
        .create(config, SignatureValidationStrategies.requireAnySignature());

    byte[] buf = IMPORTANT_QUOTE_SIGNED_NOT_COMPRESSED.getBytes("US-ASCII");

    // tamper
    buf[666]++;

    final InputStream plainTextInputStream = sut
        .wrapWithDecryptAndVerify(new ByteArrayInputStream(buf));

    Streams.drain(plainTextInputStream);
  }

  @Test(expected = IOException.class)
  public void decryptingSignedMessageAndRequiringSpecificSigner_notSignedByTheCorrectKey_fails()
      throws IOException, SignatureException, NoSuchAlgorithmException {
    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    decrypt(IMPORTANT_QUOTE_SIGNED_COMPRESSED.getBytes("US-ASCII"), config,
        SignatureValidationStrategies
            .requireSignatureFromAllKeys(ExampleMessages.PUBKEY_ID_RECIPIENT));
  }

  @Test(expected = IOException.class)
  public void decryptingMultiSignedMessageAndRequiringSpecificSigner_notSignedByTheCorrectKey_fails()
      throws IOException, SignatureException, NoSuchAlgorithmException {
    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    decrypt(IMPORTANT_QUOTE_SIGNED_MULTIPLE_COMPRESSED.getBytes("US-ASCII"), config,
        SignatureValidationStrategies
            .requireSignatureFromAllKeys(ExampleMessages.PUBKEY_ID_RECIPIENT));
  }

  @Test
  public void decryptingSignedMessageAndRequiringSpecificSigner_signedByTheCorrectKey_succeeds()
      throws IOException, SignatureException, NoSuchAlgorithmException {
    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    final String decryptedQuote = decrypt(IMPORTANT_QUOTE_SIGNED_COMPRESSED.getBytes(
        "US-ASCII"),
        config,
        SignatureValidationStrategies.requireSignatureFromAllKeys(ExampleMessages.KEY_ID_SENDER));

    Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
  }

  @Test(expected = IOException.class)
  public void decryptingSignedMessageAndRequiringMultipleSpecificSigner_signedBySubsetOfTheCorrectKeys_fails()
      throws IOException, SignatureException, NoSuchAlgorithmException {
    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    decrypt(IMPORTANT_QUOTE_SIGNED_MULTIPLE_V2_COMPRESSED.getBytes("US-ASCII"), config,
        SignatureValidationStrategies.requireSignatureFromAllKeys(ExampleMessages.KEY_ID_SENDER,
            ExampleMessages.EY_ID_ANOTHER_SENDER));
  }

  @Test
  public void decryptingSignedMessageAndRequiringMultipleSpecificSigner_signedByTheCorrectKeys_succeeds()
      throws IOException, SignatureException, NoSuchAlgorithmException {
    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    final String decryptedQuote = decrypt(
        IMPORTANT_QUOTE_SIGNED_BY_2_KNOWN_1_UNKNOWN_KEY.getBytes("US-ASCII"), config,
        SignatureValidationStrategies.requireSignatureFromAllKeys(ExampleMessages.KEY_ID_SENDER,
            ExampleMessages.KEY_ID_SENDER_2));

    Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
  }


  @Test
  public void decryptingSignedMessageAndRequiringSpecificSigner_signedByTheCorrectKeyAndOthers_succeeds()
      throws IOException, SignatureException, NoSuchAlgorithmException {
    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    final String decryptedQuote = decrypt(
        IMPORTANT_QUOTE_SIGNED_MULTIPLE_COMPRESSED.getBytes("US-ASCII"), config,
        SignatureValidationStrategies.requireSignatureFromAllKeys(ExampleMessages.KEY_ID_SENDER));

    Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
  }

  @Test(expected = IOException.class)
  public void decryptingMessage_withoutHavingSecretKey_fails()
      throws IOException, SignatureException {
    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    decrypt(IMPORTANT_QUOTE_NOT_ENCRYPTED_TO_ME.getBytes("US-ASCII"), config,
        SignatureValidationStrategies.ignoreSignatures());
  }

  @Test(expected = IOException.class)
  public void decryptingUnsignedMessage_butAnySignatureIsRequired_fails()
      throws IOException, SignatureException {
    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    final String decryptedQuote = decrypt(
        IMPORTANT_QUOTE_NOT_SIGNED_NOT_COMPRESSED.getBytes("US-ASCII"), config,
        SignatureValidationStrategies.requireAnySignature());

    Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
  }

  @Test(expected = IOException.class)
  public void decryptingUnsignedMessage_butSpecificSignatureIsRequired_fails()
      throws IOException, SignatureException {
    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    final String decryptedQuote = decrypt(
        IMPORTANT_QUOTE_NOT_SIGNED_NOT_COMPRESSED.getBytes("US-ASCII"), config,
        SignatureValidationStrategies.requireSignatureFromAllKeys(ExampleMessages.KEY_ID_SENDER));

    Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
  }

  @Test
  public void decryptingUnsignedMessage_andSignatureIsNotRequired_succeeds()
      throws IOException, SignatureException {
    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    final String decryptedQuote = decrypt(
        IMPORTANT_QUOTE_NOT_SIGNED_NOT_COMPRESSED.getBytes("US-ASCII"), config,
        SignatureValidationStrategies.ignoreSignatures());

    Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
  }

  @Test
  public void decryptingSignedMessage_andSignatureIsNotRequired_succeeds()
      throws IOException, SignatureException {
    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    final String decryptedQuote = decrypt(IMPORTANT_QUOTE_SIGNED_COMPRESSED.getBytes(
        "US-ASCII"),
        config, SignatureValidationStrategies.ignoreSignatures());

    Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
  }

  @Test
  public void decryptingSignedMessageWithSingleeSignatures_andAnySignatureIsRequired_succeeds()
      throws IOException, SignatureException {
    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    final String decryptedQuote = decrypt(IMPORTANT_QUOTE_SIGNED_COMPRESSED.getBytes(
        "US-ASCII"),
        config, SignatureValidationStrategies.requireAnySignature());

    Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
  }

  @Test
  public void decryptingSignedMessageWithMultipleSignaturesKnownSignatureFirst_andAnySignatureIsRequired_succeeds()
      throws IOException, SignatureException {
    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    final String decryptedQuote = decrypt(
        IMPORTANT_QUOTE_SIGNED_MULTIPLE_COMPRESSED.getBytes("US-ASCII"), config,
        SignatureValidationStrategies.requireAnySignature());

    Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
  }

  @Test
  public void decryptingSignedMessageWithMultipleSignaturesUnknownSignatureFirst_andAnySignatureIsRequired_succeeds()
      throws IOException, SignatureException {
    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

    final String decryptedQuote = decrypt(
        IMPORTANT_QUOTE_SIGNED_MULTIPLE_V2_COMPRESSED.getBytes("US-ASCII"), config,
        SignatureValidationStrategies.requireAnySignature());

    Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
  }

}
package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeNotNull;
import static org.mockito.Mockito.mock;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;
import org.junit.Before;
import org.junit.Test;

public class BuildDecryptionInputStreamAPITest {

  @Before
  public void installBCProvider() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test(expected = NullPointerException.class)
  public void decryptConfigure_NoConfigPassed_throws() throws Exception {
    BouncyGPG.decryptAndVerifyStream().withConfig(null);
  }

  @Test
  public void decryptConfigure_ConfigPassed_notNull() throws Exception {
    assertNotNull(BouncyGPG.decryptAndVerifyStream().withConfig(mock(KeyringConfig.class)));
  }

  @Test
  public void decryptConfigureValidate_notNull() throws Exception {
    final BuildDecryptionInputStreamAPI.Validation withConfig = BouncyGPG.decryptAndVerifyStream()
        .withConfig(mock(KeyringConfig.class));
    assumeNotNull(withConfig);

    assertNotNull(withConfig.andValidateSomeoneSigned());
    assertNotNull(withConfig.andIgnoreSignatures());
    assertNotNull(withConfig.andRequireSignatureFromAllKeys(1L));
  }

  @Test(expected = NullPointerException.class)
  public void decryptConfigureValidate_pasNullCiphertext_throws() throws Exception {
    final BuildDecryptionInputStreamAPI.Build build = BouncyGPG.decryptAndVerifyStream()
        .withConfig(mock(KeyringConfig.class)).andIgnoreSignatures();
    build.fromEncryptedInputStream(null);

  }

  @Test(expected = IllegalArgumentException.class)
  public void decryptValidateSpecificKeysLong_passNoKeys_throws() throws Exception {
    final BuildDecryptionInputStreamAPI.Validation validation = BouncyGPG.decryptAndVerifyStream()
        .withConfig(mock(KeyringConfig.class));
    assumeNotNull(validation);

    validation.andRequireSignatureFromAllKeys(new Long[]{});
  }

  @Test(expected = IllegalArgumentException.class)
  public void decryptValidateSpecificKeysUserId_passNoKeys2_throws() throws Exception {
    final BuildDecryptionInputStreamAPI.Validation validation = BouncyGPG.decryptAndVerifyStream()
        .withConfig(mock(KeyringConfig.class));
    assumeNotNull(validation);

    validation.andRequireSignatureFromAllKeys(new String[]{});
  }

  @Test()
  public void decryptAndValidateSignature_withGoodSettings_works() throws Exception {

    try (InputStream ciphertext = new ByteArrayInputStream(
        ExampleMessages.IMPORTANT_QUOTE_SIGNED_COMPRESSED.getBytes("US-ASCII"))) {
      final InputStream plaintextStream = BouncyGPG.decryptAndVerifyStream()
          .withConfig(Configs.keyringConfigFromResourceForRecipient())
          .andRequireSignatureFromAllKeys("sender@example.com")
          .fromEncryptedInputStream(ciphertext);

      final String plainText = inputStreamToText(plaintextStream);

      assertThat(plainText, equalTo(ExampleMessages.IMPORTANT_QUOTE_TEXT));
      plaintextStream.close();
    }
  }

  @Test()
  public void decryptAndValidateSignature_withSignatureWithSignOnlyCapability_works()
      throws Exception {

    try (InputStream ciphertext = new ByteArrayInputStream(
        ExampleMessages.IMPORTANT_QUOTE_SIGNED_BY_SIGN_ONLY_DSA_KEY.getBytes("US-ASCII"))) {
      final InputStream plaintextStream = BouncyGPG.decryptAndVerifyStream()
          .withConfig(Configs.keyringConfigFromResourceForRecipient())
          .andRequireSignatureFromAllKeys("sender.signonly@example.com")
          .fromEncryptedInputStream(ciphertext);

      final String plainText = inputStreamToText(plaintextStream);

      assertThat(plainText, equalTo(ExampleMessages.IMPORTANT_QUOTE_TEXT));
      plaintextStream.close();
    }
  }


  @Test()
  public void decryptNoSignatureValidation_withUnsignedData_works() throws Exception {

    try (InputStream ciphertext = new ByteArrayInputStream(
        ExampleMessages.IMPORTANT_QUOTE_NOT_SIGNED_NOT_COMPRESSED.getBytes("US-ASCII"))) {
      final InputStream plaintextStream = BouncyGPG.decryptAndVerifyStream()
          .withConfig(Configs.keyringConfigFromResourceForRecipient())
          .andIgnoreSignatures()
          .fromEncryptedInputStream(ciphertext);

      final String plainText = inputStreamToText(plaintextStream);

      assertThat(plainText, equalTo(ExampleMessages.IMPORTANT_QUOTE_TEXT));
      plaintextStream.close();
    }
  }

  @Test(expected = IOException.class)
  public void decryptAndValidateSignature_withUnsignedData_throws() throws Exception {

    try (InputStream ciphertext = new ByteArrayInputStream(
        ExampleMessages.IMPORTANT_QUOTE_NOT_SIGNED_NOT_COMPRESSED.getBytes("US-ASCII"))) {
      final InputStream plaintextStream = BouncyGPG.decryptAndVerifyStream()
          .withConfig(Configs.keyringConfigFromResourceForRecipient())
          .andRequireSignatureFromAllKeys("sender@example.com")
          .fromEncryptedInputStream(ciphertext);

      Streams.drain(plaintextStream);
    }
  }

  private String inputStreamToText(InputStream in) throws IOException {
    ByteArrayOutputStream res = new ByteArrayOutputStream();
    Streams.pipeAll(in, res);
    res.close();
    return res.toString();
  }
}
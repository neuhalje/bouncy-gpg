package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.Pre202KeySelectionStrategy.extractSecretSigningKeyFromKeyrings;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages.IMPORTANT_QUOTE_SIGNED_BY_2_KNOWN_1_UNKNOWN_KEY;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages.IMPORTANT_QUOTE_SIGNED_MULTIPLE_COMPRESSED;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages.IMPORTANT_QUOTE_TEXT;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting.DecryptionStreamFactory;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy.PURPOSE;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationStrategies;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationStrategy;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.util.io.Streams;
import org.hamcrest.CoreMatchers;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * This tests for a BROKEN feature!
 *
 * This tests that the pre-202 implementation and the strategy select the same
 * keys.
 *
 * These tests also include stray tests from other classes.
 */
public class Pre202KeySelectionStrategyTest {


  private static final long PRIVATE_MASTER_KEY_RECIPIENT = 0x3DF16BD7C3F280F3L;
  private static final char[] PRIVATE_MASTER_KEY_RECIPIENT_PASSPHRASE = "recipient".toCharArray();
  private static final long PRIVATE_SUB_KEY_RECIPIENT = 0x54A3DB374F787AB7L;
  private static final long PRIVATE_KEY_ID__ONLY_HAVE_PUB_KEY = 0xaff0658d23fb56e6L;

  @Before
  public void before() {
    BouncyGPG.registerProvider();
  }

  @Test
  public void correct_signingKey_isSelected() throws IOException, PGPException {
    final KeyringConfig keyringConfig = RFC4880TestKeyringsDedicatedSigningKey
        .publicKeyOnlyKeyringConfig();

    KeySelectionStrategy sut = new Pre202KeySelectionStrategy();

    final PGPPublicKey signingPublicKey = sut
        .selectPublicKey(PURPOSE.FOR_SIGNING, RFC4880TestKeyringsDedicatedSigningKey.UID_EMAIL,
            keyringConfig);

    final long selectedKeyId = signingPublicKey.getKeyID();

    // this is not what the RFC expects but what the pre 202 behaviour is
    assertEquals("It should  select the encryption key",
        RFC4880TestKeyringsDedicatedSigningKey.ENCRYPTION_KEY,
        selectedKeyId);

  }

  @Test
  public void oldAndNewImplementation_seelctSameSigningKey() throws IOException, PGPException {
    final KeyringConfig keyringConfig = RFC4880TestKeyringsDedicatedSigningKey
        .publicAndPrivateKeyKeyringConfig();

    final PGPSecretKey pgpSecPre202 =
        extractSecretSigningKeyFromKeyrings(keyringConfig.getSecretKeyRings(),
            RFC4880TestKeyringsDedicatedSigningKey.UID_EMAIL);

    KeySelectionStrategy sut = new Pre202KeySelectionStrategy();

    final PGPPublicKey selectedPublicKey = sut
        .selectPublicKey(PURPOSE.FOR_SIGNING, RFC4880TestKeyringsDedicatedSigningKey.UID_EMAIL,
            keyringConfig);

    assertEquals("Old and new should select the same private key", pgpSecPre202.getKeyID(),
        selectedPublicKey.getKeyID());

  }

  private PGPPublicKeyRing getPgpPublicKeyring(KeyringConfig keyringConfig)
      throws IOException, PGPException {
    // only one keyring in the example
    return keyringConfig.getPublicKeyRings().getKeyRings().next();
  }

  @Test()
  public void extracting_exitingSigningPubKeyByName_returnsKey() throws Exception {

    KeySelectionStrategy sut = new Pre202KeySelectionStrategy();

    KeyringConfig keyringConfig = Configs.keyringConfigFromResourceForRecipient(
        KeyringConfigCallbacks.withPassword(PRIVATE_MASTER_KEY_RECIPIENT_PASSPHRASE));

    final PGPPublicKey pgpPublicKey = sut
        .selectPublicKey(PURPOSE.FOR_SIGNING, "sender@example.com", keyringConfig);
    assertThat(pgpPublicKey, Matchers.notNullValue());
    assertThat(pgpPublicKey.getKeyID(), equalTo(ExampleMessages.KEY_ID_SENDER));
  }

  @Test()
  public void extracting_anothereExitingSigningPubKeyByName_returnsKey() throws Exception {

    KeySelectionStrategy sut = new Pre202KeySelectionStrategy();

    KeyringConfig keyringConfig = Configs.keyringConfigFromResourceForRecipient(
        KeyringConfigCallbacks.withPassword(PRIVATE_MASTER_KEY_RECIPIENT_PASSPHRASE));

    final PGPPublicKey pgpPublicKey = sut
        .selectPublicKey(PURPOSE.FOR_SIGNING, "sender2@example.com", keyringConfig);

    assertThat(pgpPublicKey, Matchers.notNullValue());
    assertThat(pgpPublicKey.getKeyID(), equalTo(ExampleMessages.KEY_ID_SENDER_2));
  }


  @Test
  public void usingSingleUserIdToSignatureValidationSelectKeys_isResolvable_verificationSucceeds()
      throws IOException, SignatureException, NoSuchAlgorithmException, PGPException {
    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();
    KeySelectionStrategy sut = new Pre202KeySelectionStrategy();

    final String decryptedQuote = decrypt(
        IMPORTANT_QUOTE_SIGNED_MULTIPLE_COMPRESSED.getBytes("US-ASCII"), config,
        SignatureValidationStrategies
            .requireSignatureFromAllKeys(sut, config, "sender@example.com"));

    Assert.assertThat(decryptedQuote, CoreMatchers.equalTo(IMPORTANT_QUOTE_TEXT));
  }

  @Test
  public void usingUserIdsToSignatureValidationSelectKeys_allKeysResolvable_verificationSucceeds()
      throws IOException, SignatureException, NoSuchAlgorithmException, PGPException {
    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();
    KeySelectionStrategy sut = new Pre202KeySelectionStrategy();

    final String decryptedQuote = decrypt(
        IMPORTANT_QUOTE_SIGNED_BY_2_KNOWN_1_UNKNOWN_KEY.getBytes("US-ASCII"), config,
        SignatureValidationStrategies
            .requireSignatureFromAllKeys(sut, config, "sender@example.com",
                "sender2@example.com"));

    Assert.assertThat(decryptedQuote, CoreMatchers.equalTo(IMPORTANT_QUOTE_TEXT));
  }

  @Test(expected = PGPException.class)
  public void usingUserIdsToSignatureValidationSelectKeys_oneKeyNotResolvable_fails()
      throws IOException, SignatureException, NoSuchAlgorithmException, PGPException {
    final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();
    KeySelectionStrategy sut = new Pre202KeySelectionStrategy();

    SignatureValidationStrategies
        .requireSignatureFromAllKeys(sut, config, "sender@example.com",
            "unknown@example.com");
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

}
package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keyrings;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.Security;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.hamcrest.text.IsEmptyString;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class KeyringConfigsTest {

  @SuppressWarnings("WeakerAccess")
  @Parameterized.Parameter
  public /* NOT private */ KeyringConfig keyringConfig;

  /*
   * make sure that the tests work independently of the way the config has been created
   */
  @Parameterized.Parameters
  public static Object[] data() throws IOException, PGPException {
    return new Object[]{Configs.keyringConfigFromFilesForSender(),
        Configs.keyringConfigFromResourceForSender(),
        Configs.keyringConfigInMemoryForSender()};
  }

  @Before
  public void before() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  public void toString_returns_nonEmptyString() throws Exception {
    assertThat(keyringConfig.toString(), is(not(IsEmptyString.isEmptyString())));
  }

  @Test
  public void getKeyFingerPrintCalculator_returnsNonNull() throws IOException, PGPException {
    assertNotNull(keyringConfig.getKeyFingerPrintCalculator());
  }

  @Test
  public void doesNotThrow() throws IOException, PGPException {
    assertThat(keyringConfig.getPublicKeyRings(), is(notNullValue()));
    assertThat(keyringConfig.getSecretKeyRings(), is(notNullValue()));
  }

  @Test
  public void loading_doesNotThrow() throws IOException, PGPException {
    assertThat(keyringConfig.getPublicKeyRings(), is(notNullValue()));
    assertThat(keyringConfig.getSecretKeyRings(), is(notNullValue()));
  }

  @Test
  public void findPubKeys_works() throws IOException, PGPException {
    assertTrue(keyringConfig.getPublicKeyRings().contains(ExampleMessages.KEY_ID_SENDER));
    assertTrue(keyringConfig.getPublicKeyRings().contains(ExampleMessages.KEY_ID_SENDER_2));
    assertTrue(keyringConfig.getPublicKeyRings().contains(ExampleMessages.PUBKEY_ID_RECIPIENT));
  }


  @Test
  public void findSecretKeyRsa_works() throws IOException, PGPException {
    assertTrue(keyringConfig.getSecretKeyRings().contains(ExampleMessages.KEY_ID_SENDER));
  }

  @Test
  public void findSecretKeyDSA_works() throws IOException, PGPException {
    assertTrue(
        keyringConfig.getSecretKeyRings().contains(ExampleMessages.KEY_ID_SENDER_DSA_SIGN_ONLY));
  }


  // non parametrised
  @Test
  public void loadingEmptyKeyRing_doesNotThrow() throws IOException, PGPException {
    KeyringConfig cfg = KeyringConfigs
        .forGpgExportedKeys(KeyringConfigCallbacks.withUnprotectedKeys());

    assertThat(cfg.getPublicKeyRings(), is(notNullValue()));
    assertThat(cfg.getSecretKeyRings(), is(notNullValue()));
  }

}
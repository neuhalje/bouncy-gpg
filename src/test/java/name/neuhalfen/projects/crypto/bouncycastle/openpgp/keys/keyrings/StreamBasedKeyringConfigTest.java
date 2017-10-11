package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.io.InputStream;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting.EncryptWithOpenPGPTestDriverTest;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import org.bouncycastle.openpgp.PGPException;
import org.hamcrest.Matchers;
import org.junit.Test;

public class StreamBasedKeyringConfigTest {

  static final KeyringConfigCallback KEYRING_CONFIG_CALLBACK = KeyringConfigCallbacks
      .withPasswordsFromMap(ExampleMessages.ALL_KEYRINGS_PASSWORDS);

  @Test
  public void nullStreams_createsKeyRingConfig() throws IOException, PGPException {
    final KeyringConfig build = StreamBasedKeyringConfig.build(
        KEYRING_CONFIG_CALLBACK, null, null);

    assertNotNull("KeyringConfig should be created", build);
  }

  @Test
  public void nullStreams_returnEmptyPublicKeyRings() throws IOException, PGPException {
    final KeyringConfig build = StreamBasedKeyringConfig.build(
        KEYRING_CONFIG_CALLBACK, null, null);

    assertNotNull("PublicKeyRings should be created", build.getPublicKeyRings());
    assertThat("PublicKeyRings should be empty", build.getPublicKeyRings().size(), is(0));
  }

  @Test
  public void nullStreams_returnEmptySecretKeyRings() throws IOException, PGPException {
    final KeyringConfig build = StreamBasedKeyringConfig.build(
        KEYRING_CONFIG_CALLBACK, null, null);

    assertNotNull("SecretKeyRings should be created", build.getSecretKeyRings());
    assertThat("SecretKeyRings should be empty", build.getSecretKeyRings().size(), is(0));
  }

  private InputStream pubKeyInputStream() {
    return EncryptWithOpenPGPTestDriverTest.class.getClassLoader().getResourceAsStream("recipient.gpg.d/pubring.gpg");
  }

  private InputStream secretKeyInputStream() {
    return EncryptWithOpenPGPTestDriverTest.class.getClassLoader().getResourceAsStream("recipient.gpg.d/secring.gpg");
  }

  @Test
  public void streams_returnPublicKeyRings() throws IOException, PGPException {
    final KeyringConfig build = StreamBasedKeyringConfig.build(
        KEYRING_CONFIG_CALLBACK, pubKeyInputStream(), null);

    assertNotNull("PublicKeyRings should be created", build.getPublicKeyRings());
    assertThat("PublicKeyRings should not be empty", build.getPublicKeyRings().size(), Matchers.greaterThan(0));
  }


  @Test
  public void streams_returnSecretKeyRings() throws IOException, PGPException {
    final KeyringConfig build = StreamBasedKeyringConfig.build(
        KEYRING_CONFIG_CALLBACK, null, secretKeyInputStream());

    assertNotNull("SecretKeyRings should be created", build.getSecretKeyRings());
    assertThat("SecretKeyRings should not be empty", build.getSecretKeyRings().size(), Matchers.greaterThan(0));
  }
}
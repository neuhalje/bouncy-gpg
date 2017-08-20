package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages.FULL_USER_ID_SENDER;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages.KEY_ID_SENDER;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages.PUBKEY_SENDER;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages.SECRET_KEY_SENDER;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.util.Iterator;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.junit.Test;


public class InMemoryKeyringTest {


  @Test
  public void getKeyFingerPrintCalculator_returnsSomething() throws IOException, PGPException {
    final InMemoryKeyring sut = new InMemoryKeyring(mock(KeyringConfigCallback.class));

    assertNotNull(sut.getKeyFingerPrintCalculator());
  }

  @Test(expected = IllegalArgumentException.class)
  public void create_passNullAsCallback_throws() throws IOException, PGPException {
    new InMemoryKeyring(null);
  }

  @Test
  public void emptyKeyring_queryPubrings_returnsEmptySet() throws IOException, PGPException {
    final InMemoryKeyring sut = new InMemoryKeyring(mock(KeyringConfigCallback.class));

    final PGPPublicKeyRingCollection publicKeyRings = sut.getPublicKeyRings();
    assertNotNull(publicKeyRings);
    assertThat(publicKeyRings.size(), is(equalTo(0)));
  }

  @Test
  public void emptyKeyring_queryPrivateRings_returnsEmptySet() throws IOException, PGPException {
    final InMemoryKeyring sut = new InMemoryKeyring(mock(KeyringConfigCallback.class));

    final PGPSecretKeyRingCollection secretKeyRings = sut.getSecretKeyRings();
    assertNotNull(secretKeyRings);
    assertThat(secretKeyRings.size(), is(equalTo(0)));
  }

  @Test
  public void emptyKeyRing_addValidPubkey_pubKeyExists() throws IOException, PGPException {
    final InMemoryKeyring sut = new InMemoryKeyring(mock(KeyringConfigCallback.class));
    sut.addPublicKey(PUBKEY_SENDER.getBytes());

    final PGPPublicKeyRingCollection publicKeyRings = sut.getPublicKeyRings();
    assertThat("A public key is found", publicKeyRings.size(), is(equalTo(1)));

    final Iterator<PGPPublicKeyRing> keyRingsWithSenderKey = publicKeyRings
        .getKeyRings(FULL_USER_ID_SENDER);
    assertTrue("The keyring is found", keyRingsWithSenderKey.hasNext());
    assertNotNull("The key is found", keyRingsWithSenderKey.next().getPublicKey(KEY_ID_SENDER));
  }

  @Test(expected = IOException.class)
  public void emptyKeyRing_tryToAddSecretkeyAsPublicKey_throws() throws IOException, PGPException {
    final InMemoryKeyring sut = new InMemoryKeyring(mock(KeyringConfigCallback.class));
    sut.addPublicKey(SECRET_KEY_SENDER.getBytes());
  }

  @Test(expected = IOException.class)
  public void emptyKeyRing_tryToAddGarbageAsPublicKey_throws() throws IOException, PGPException {
    final InMemoryKeyring sut = new InMemoryKeyring(mock(KeyringConfigCallback.class));
    sut.addPublicKey("garbage".getBytes());
  }


  @Test(expected = IllegalArgumentException.class)
  public void emptyKeyRing_tryToNullAsPublicKey_throws() throws IOException, PGPException {
    final InMemoryKeyring sut = new InMemoryKeyring(mock(KeyringConfigCallback.class));
    sut.addPublicKey(null);
  }

  @Test(expected = IOException.class)
  public void emptyKeyRing_tryToAddGarbageAsSecretKey_throws() throws IOException, PGPException {
    final InMemoryKeyring sut = new InMemoryKeyring(mock(KeyringConfigCallback.class));
    sut.addSecretKey("garbage".getBytes());
  }

  @Test(expected = IOException.class)
  public void emptyKeyRing_tryToAddPubkeyAsSecretKey_throws() throws IOException, PGPException {
    final InMemoryKeyring sut = new InMemoryKeyring(mock(KeyringConfigCallback.class));
    sut.addSecretKey(PUBKEY_SENDER.getBytes());
  }

  @Test
  public void emptyKeyRing_addValidSecretKey_pubKeyIsNotImported()
      throws IOException, PGPException {
    final InMemoryKeyring sut = new InMemoryKeyring(mock(KeyringConfigCallback.class));
    sut.addSecretKey(SECRET_KEY_SENDER.getBytes());

    final PGPPublicKeyRingCollection publicKeyRings = sut.getPublicKeyRings();
    assertThat("Public key is not imported", publicKeyRings.size(), is(equalTo(0)));
  }

  @Test
  public void emptyKeyRing_addValidSecretKey_secretKeyExists() throws IOException, PGPException {
    final InMemoryKeyring sut = new InMemoryKeyring(mock(KeyringConfigCallback.class));
    sut.addSecretKey(SECRET_KEY_SENDER.getBytes());

    final PGPSecretKeyRingCollection secretKeyRings = sut.getSecretKeyRings();
    assertThat("A secret key is found", secretKeyRings.size(), is(equalTo(1)));

    final Iterator<PGPSecretKeyRing> keyRingsWithSenderKey = secretKeyRings
        .getKeyRings(FULL_USER_ID_SENDER);
    assertTrue("The keyring is found", keyRingsWithSenderKey.hasNext());
    assertNotNull("The key is found", keyRingsWithSenderKey.next().getPublicKey(KEY_ID_SENDER));
  }

  @Test(expected = IllegalArgumentException.class)
  public void emptyKeyRing_tryToNullAsSecretKey_throws() throws IOException, PGPException {
    final InMemoryKeyring sut = new InMemoryKeyring(mock(KeyringConfigCallback.class));
    sut.addSecretKey(null);
  }
}
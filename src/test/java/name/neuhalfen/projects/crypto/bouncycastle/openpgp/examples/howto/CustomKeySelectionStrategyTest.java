package name.neuhalfen.projects.crypto.bouncycastle.openpgp.examples.howto;


import static org.junit.Assert.assertFalse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Iterator;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.util.Iterable;
import org.bouncycastle.util.io.Streams;
import org.junit.Before;
import org.junit.Test;

/**
 * I cant find a way to define a key strategy any other beyond by email, this is a problem because
 * I don't know name ID of the key sent to me. I only need to use this public key to encrypt to
 * my sender.
 *
 * In the end would be awesome have an option to KeySelectionStrategy such as:
 *
 * <pre><code>
 * byte[] myOwnPrivateKey = DB.getMyPrivateKey();
 * byte[] customerPublicKey = DB.getCustomerPrivateKey();
 *
 * final OutputStream encryptionStream = BouncyGPG
 * .encryptToStream()
 * .toRecipient(customerPublicKey)
 * .andSignWith(myOwnPrivateKey)
 * .armorAsciiOutput()
 * .andWriteTo(buffer);
 * </code></pre>
 *
 * <a href="https://github.com/neuhalje/bouncy-gpg/issues/26">https://github.com/neuhalje/bouncy-gpg/issues/26</a>
 */
public class CustomKeySelectionStrategyTest {


  @Before
  public void installBCProvider() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 0);
    }
  }

  /**
   * Send a message by extracting the userIds from the keys themselves.
   */
  @Test
  public void extractingUserIdFromKeyExample()
      throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {

    // sender needs his own public and private key, and the recipients public key
    final byte[] recipientPubKey = ExampleMessages.PUBKEY_RECIPIENT.getBytes();

    final byte[] senderPublicKey = ExampleMessages.PUBKEY_SENDER.getBytes();
    final byte[] senderPrivateKey = ExampleMessages.SECRET_KEY_SENDER.getBytes();

    final String senderPrivateKeyPassphrase = "sender";

    // Prepare the keyring
    final InMemoryKeyring keyring = KeyringConfigs
        .forGpgExportedKeys(KeyringConfigCallbacks.withPassword(senderPrivateKeyPassphrase));

    keyring.addPublicKey(recipientPubKey);

    keyring.addSecretKey(senderPrivateKey);

    // at this stage the public keyring, and the private keyring contain only ONE key
    final String sendersPrivateKeyUserId = firstUidForKeyRings(keyring.getSecretKeyRings());
    final String recipientsPublicKeyUserId = firstUidForKeyRings(keyring.getPublicKeyRings());

    // Hack: we add the senders public key after extracting the recipients userid
    // Alternatively we could parse the keys "by hand"
    keyring.addPublicKey(senderPublicKey);

    final ByteArrayOutputStream encryptedData = new ByteArrayOutputStream();

    try (
        final OutputStream encryptionStream = BouncyGPG
            .encryptToStream()
            .withConfig(keyring)
            .withStrongAlgorithms()
            .toRecipient(recipientsPublicKeyUserId)
            .andSignWith(sendersPrivateKeyUserId)
            .armorAsciiOutput()
            .andWriteTo(encryptedData);
        final ByteArrayInputStream plaintext = new ByteArrayInputStream("Hello world".getBytes())
    ) {
      Streams.pipeAll(plaintext, encryptionStream);
    }

    encryptedData.close();
    byte[] chipertext = encryptedData.toByteArray();
  }

  /*
   * return the first userid of the first key in the first keyring.
   */
  private String firstUidForKeyRings(Iterable<? extends PGPKeyRing> keyRings) {
    // Watch Demeters Law scream in agony

    final Iterator<? extends PGPKeyRing> keyRingIterator = keyRings.iterator();
    final PGPKeyRing firstKeyRing = keyRingIterator.next();
    assertFalse("Not stable with more than one keyring", keyRingIterator.hasNext());

    final PGPPublicKey firstKeyInFirstKeyring = firstKeyRing.getPublicKey();

    // any userid of this key will suffice
    return firstKeyInFirstKeyring.getUserIDs().next();
  }

}

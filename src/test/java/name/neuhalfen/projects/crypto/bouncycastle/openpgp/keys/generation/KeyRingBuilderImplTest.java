package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.KeyMatcher.secretKeyRingForUid;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.KeyMatcher.secretKeyRingHasRoles;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.iterableWithSize;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.length.RsaLength;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.KeyMatcher;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.SecretKeyringKeyRoleMatcher.KeyRole;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.junit.Before;
import org.junit.Test;

public class KeyRingBuilderImplTest {

  @Before
  public void installBCProvider() {
    BouncyGPG.registerProvider();
  }

  private final static String UID_JULIET = "Juliet Capulet <juliet@example.com>";
  private final static String EMAIL_JULIET = "<juliet@example.com>";

  @Test
  public void simpleEcKeyRing_createsGoodKeys()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

    // Verify that 'simpleEcKeyRing' creates good keys (correct uid, keytype, ..)

    KeyRingBuilderImpl sut = new KeyRingBuilderImpl();

    final KeyringConfig keyRing = sut.simpleEcKeyRing(UID_JULIET);

    validateSimpleKeyRing(keyRing);

    //  keyRing.getPublicKeyRings().getKeyRings().next().getPublicKey().is
  //  assertThat("No passphrase is set",
  //      keyRing.getSecretKeyRings().getKeyRings().next().getSecretKey().);
  }


  @Test
  public void simpleRsaKeyRing_createsGoodKeys()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

    // Verify that 'simpleEcKeyRing' creates good keys (correct uid, keytype, ..)

    KeyRingBuilderImpl sut = new KeyRingBuilderImpl();

    final KeyringConfig keyRing = sut.simpleRsaKeyRing(UID_JULIET, RsaLength.RSA_1024_BIT);

    validateSimpleKeyRing(keyRing);

    //  keyRing.getPublicKeyRings().getKeyRings().next().getPublicKey().is
    //  assertThat("No passphrase is set",
    //      keyRing.getSecretKeyRings().getKeyRings().next().getSecretKey().);
  }

  private void validateSimpleKeyRing(final KeyringConfig keyRing) throws IOException, PGPException {
    assertNotNull("A keyring should be created", keyRing);

    final PGPPublicKeyRingCollection pubKeyRings = keyRing.getPublicKeyRings();
    assertThat("Juliets public key should be created",
        pubKeyRings, contains(
            KeyMatcher.pubKeyRingForUid(EMAIL_JULIET)
        ));

    assertThat("Only one public key should be created",
        pubKeyRings, iterableWithSize(1)
    );

    final PGPSecretKeyRingCollection secretKeyRings = keyRing.getSecretKeyRings();
    assertThat("Juliets secret key should be created",
        secretKeyRings,

        contains(
            allOf(
                secretKeyRingForUid(EMAIL_JULIET),
                secretKeyRingHasRoles(KeyRole.MASTER, KeyRole.ENCRYPTION, KeyRole.SIGNING)
            )));

    assertThat("Only one secret key should be created",
        secretKeyRings, iterableWithSize(1)
    );
  }
}
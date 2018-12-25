package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.KeyMatcher.hasKeyLength;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.KeyMatcher.keyAlgorithmAnyOf;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.everyItem;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Collection;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PublicKeyAlgorithm;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.ECDHKeyType;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.ECDSAKeyType;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.curve.EllipticCurve;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.Iterable;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/*
 Verify that all elliptic curves are supported
 */
@RunWith(Parameterized.class)
public class EccKeyRingTest {

  private final static String UID_JULIET = "Juliet Capulet <juliet@example.com>";

  @Parameters
  public static Collection<Object[]> curves() {
    return Arrays.asList(new Object[][]{
        {EllipticCurve.CURVE_NIST_P256, 256},
        {EllipticCurve.CURVE_NIST_P384, 384},
        {EllipticCurve.CURVE_NIST_P521, 521}
    });
  }

  @Parameter(0)
  public EllipticCurve curve;
  @Parameter(1)
  public Integer keyLength;

  @Before
  public void installBCProvider() {
    BouncyGPG.registerProvider();
  }

  @Test
  public void createEccKeyRing_works()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

    final KeyringConfig keyringConfig = BouncyGPG.createKeyring().withSubKey(
        KeySpec.getBuilder(ECDHKeyType.fromCurve(curve))
            .withKeyFlags(KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS)
            .withDefaultAlgorithms())
        .withMasterKey(
            KeySpec.getBuilder(ECDSAKeyType.fromCurve(curve))
                .withKeyFlags(KeyFlag.AUTHENTICATION, KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                .withDefaultAlgorithms())
        .withPrimaryUserId(UID_JULIET)
        .withoutPassphrase()
        .build();

    final Iterable<PGPSecretKeyRing> secretKeyRings = keyringConfig.getSecretKeyRings();
    secretKeyRings.forEach(keyRing ->
        assertThat("We want ECC keys of correct length",
            keyRing,
            everyItem(
                allOf(
                    keyAlgorithmAnyOf(
                        PublicKeyAlgorithm.ECDH, PublicKeyAlgorithm.ECDSA
                    ),
                    hasKeyLength(keyLength)
                )
            )));
  }

}

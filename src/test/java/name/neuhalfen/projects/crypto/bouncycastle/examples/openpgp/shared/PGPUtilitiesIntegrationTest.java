package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.shared;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.DecryptionConfig;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.security.Security;

import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(Parameterized.class)
public class PGPUtilitiesIntegrationTest {

    /*
     * make sure that the tests work independently of the way the config has been created
     */
    @Parameterized.Parameters
    public static Object[] data() {
        return new Object[]{Configs.buildConfigForDecryptionFromResources(), Configs.buildConfigForDecryptionFromFiles()};
    }


    @Parameterized.Parameter
    public /* NOT private */ DecryptionConfig decryptionConfig;


    private static final long KEY_ID_WITH_PRIVATE_KEY = 0x3DF16BD7C3F280F3l;

    @Before
    public void before() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test(expected = PGPException.class)
    public void extracting_nonExitingPubKey_throws() throws Exception {
        PGPUtilities.extractPublicKey("unknown@example.com", exampleCollection());
    }

    @Test()
    public void extracting_exitingPubKey_returnsKeys() throws Exception {
        final PGPPublicKeyRing publicKeys = PGPUtilities.extractPublicKey("recipient@example.com", exampleCollection());
        assertThat(publicKeys, Matchers.notNullValue());
    }

    @Test()
    public void extracting_exitingPubKey2_returnsKeys() throws Exception {
        final PGPPublicKeyRing publicKeys = PGPUtilities.extractPublicKey("sender@example.com", exampleCollection());
        assertThat(publicKeys, Matchers.notNullValue());

    }

    @Test()
    public void extractingPrivateKey_withGoodPassword_returnsKey() throws Exception {

        final PGPSecretKeyRingCollection secretKeyRings = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(decryptionConfig.getSecretKeyRing()), new BcKeyFingerprintCalculator());
        final PGPPrivateKey pgpPrivateKey = PGPUtilities.extractPrivateKey(secretKeyRings.getSecretKey(KEY_ID_WITH_PRIVATE_KEY), decryptionConfig.getDecryptionSecretKeyPassphrase().toCharArray());

        assertThat(pgpPrivateKey, Matchers.notNullValue());
    }

    @Test(expected = PGPException.class)
    public void extractingPrivateKey_withWrongPassword_throws() throws Exception {

        final PGPSecretKeyRingCollection secretKeyRings = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(decryptionConfig.getSecretKeyRing()), new BcKeyFingerprintCalculator());

        final PGPPrivateKey pgpPrivateKey = PGPUtilities.extractPrivateKey(secretKeyRings.getSecretKey(KEY_ID_WITH_PRIVATE_KEY), "wrong password".toCharArray());
    }


    PGPPublicKeyRingCollection exampleCollection() throws IOException, PGPException {

        final PGPPublicKeyRingCollection pgpPublicKeyRings = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(
                        decryptionConfig.getPublicKeyRing()), new BcKeyFingerprintCalculator());

        return pgpPublicKeyRings;
    }

}
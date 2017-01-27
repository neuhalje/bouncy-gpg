package name.neuhalfen.projects.crypto.bouncycastle.openpgp.shared;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting.DecryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
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


    private static final long PRIVATE_MASTER_KEY = 0x3DF16BD7C3F280F3l;
    private static final long PRIVATE_SUB_KEY = 0x54A3DB374F787AB7l;

    private static final long PRIVATE_KEY_ID__ONLY_HAVE_PUB_KEY = 0xaff0658d23fb56e6l;

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
    public void extracting_ownPubKey_returnsKeys() throws Exception {
        final PGPPublicKeyRing publicKeys = PGPUtilities.extractPublicKey("recipient@example.com", exampleCollection());
        assertThat(publicKeys, Matchers.notNullValue());
    }

    @Test()
    public void extracting_exitingPubKey_returnsKeys() throws Exception {
        final PGPPublicKeyRing publicKeys = PGPUtilities.extractPublicKey("sender@example.com", exampleCollection());
        assertThat(publicKeys, Matchers.notNullValue());
    }

    private PGPSecretKeyRingCollection secretKeyRings() throws IOException, PGPException {
        final PGPSecretKeyRingCollection ret = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(decryptionConfig.getSecretKeyRing()), new BcKeyFingerprintCalculator());
        return ret;
    }

    @Test()
    public void findingUnknownPrivateKey_returnsNull() throws Exception {

        final PGPSecretKeyRingCollection secretKeyRings = secretKeyRings();

        final PGPPrivateKey privateKey = PGPUtilities.findSecretKey(secretKeyRings, PRIVATE_KEY_ID__ONLY_HAVE_PUB_KEY, decryptionConfig.getDecryptionSecretKeyPassphrase().toCharArray());
        assertThat(privateKey, Matchers.nullValue());
    }

    @Test()
    public void findingPrivateMasterKey_withGoodPassword_returnsKey() throws Exception {

        final PGPSecretKeyRingCollection secretKeyRings = secretKeyRings();

        final PGPPrivateKey pgpPrivateKey = PGPUtilities.extractPrivateKey(secretKeyRings.getSecretKey(PRIVATE_MASTER_KEY), decryptionConfig.getDecryptionSecretKeyPassphrase().toCharArray());

        assertThat(pgpPrivateKey, Matchers.notNullValue());
    }

    @Test()
    public void extractingPrivateMasterKey_withGoodPassword_returnsKey() throws Exception {

        final PGPSecretKeyRingCollection secretKeyRings = secretKeyRings();
        final PGPPrivateKey pgpPrivateKey = PGPUtilities.extractPrivateKey(secretKeyRings.getSecretKey(PRIVATE_MASTER_KEY), decryptionConfig.getDecryptionSecretKeyPassphrase().toCharArray());

        assertThat(pgpPrivateKey, Matchers.notNullValue());
    }


    @Test()
    public void extractingPrivateSubKey_withGoodPassword_returnsKey() throws Exception {

        final PGPSecretKeyRingCollection secretKeyRings = secretKeyRings();
        final PGPPrivateKey pgpPrivateKey = PGPUtilities.extractPrivateKey(secretKeyRings.getSecretKey(PRIVATE_SUB_KEY), decryptionConfig.getDecryptionSecretKeyPassphrase().toCharArray());

        assertThat(pgpPrivateKey, Matchers.notNullValue());
    }

    @Test(expected = PGPException.class)
    public void extractingPrivateKey_withWrongPassword_throws() throws Exception {

        final PGPSecretKeyRingCollection secretKeyRings = secretKeyRings();

        final PGPPrivateKey pgpPrivateKey = PGPUtilities.extractPrivateKey(secretKeyRings.getSecretKey(PRIVATE_SUB_KEY), "wrong password".toCharArray());
    }


    PGPPublicKeyRingCollection exampleCollection() throws IOException, PGPException {

        final PGPPublicKeyRingCollection pgpPublicKeyRings = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(
                        decryptionConfig.getPublicKeyRing()), new BcKeyFingerprintCalculator());

        return pgpPublicKeyRings;
    }

}
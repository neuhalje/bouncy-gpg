package name.neuhalfen.projects.crypto.bouncycastle.openpgp.shared;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.security.Security;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assume.assumeNotNull;
import static org.junit.Assume.assumeThat;

@RunWith(Parameterized.class)
public class PGPUtilitiesIntegrationTest {

    /*
     * make sure that the tests work independently of the way the config has been created
     */
    @Parameterized.Parameters
    public static Object[] data() {
        return new Object[]{
                Configs.keyringConfigFromResourceForRecipient(KeyringConfigCallbacks.withPassword(PRIVATE_MASTER_KEY_RECIPIENT_PASSPHRASE)),
                Configs.keyringConfigFromFilesForRecipient(KeyringConfigCallbacks.withPassword(PRIVATE_MASTER_KEY_RECIPIENT_PASSPHRASE))};
    }


    @Parameterized.Parameter
    public /* NOT private */ KeyringConfig keyringConfig;


    private static final long PRIVATE_MASTER_KEY_RECIPIENT = 0x3DF16BD7C3F280F3L;
    private static final char[] PRIVATE_MASTER_KEY_RECIPIENT_PASSPHRASE = "recipient".toCharArray();

    private static final long PRIVATE_SUB_KEY_RECIPIENT = 0x54A3DB374F787AB7L;

    private static final long PRIVATE_KEY_ID__ONLY_HAVE_PUB_KEY = 0xaff0658d23fb56e6L;

    @Before
    public void before() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test(expected = PGPException.class)
    public void extracting_nonExitingPubKey_throws() throws Exception {
        PGPUtilities.extractPublicKeyRingForUserId("unknown@example.com", keyringConfig.getPublicKeyRings());
    }

    @Test()
    public void extracting_ownPubKey_returnsKeys() throws Exception {
        final PGPPublicKeyRing publicKeys = PGPUtilities.extractPublicKeyRingForUserId("recipient@example.com", keyringConfig.getPublicKeyRings());
        assertThat(publicKeys, Matchers.notNullValue());
    }

    @Test()
    public void extracting_exitingPubKey_returnsKeys() throws Exception {
        final PGPPublicKeyRing publicKeys = PGPUtilities.extractPublicKeyRingForUserId("sender@example.com", keyringConfig.getPublicKeyRings());
        assertThat(publicKeys, Matchers.notNullValue());
    }

    @Test()
    public void extracting_exitingSigningPubKeyByName_returnsKey() throws Exception {
        final PGPPublicKeyRing publicKeys = PGPUtilities.extractPublicKeyRingForUserId("sender@example.com", keyringConfig.getPublicKeyRings());
        assumeThat(publicKeys, Matchers.notNullValue());

        final PGPPublicKey pgpPublicKey = PGPUtilities.extractSigningPublicKey(publicKeys);
        assertThat(pgpPublicKey, Matchers.notNullValue());
        assertThat(pgpPublicKey.getKeyID(), equalTo(ExampleMessages.PUBKEY_SENDER));
    }

    @Test()
    public void extracting_anothereExitingSigningPubKeyByName_returnsKey() throws Exception {
        final PGPPublicKeyRing publicKeys = PGPUtilities.extractPublicKeyRingForUserId("sender2@example.com", keyringConfig.getPublicKeyRings());
        assumeThat(publicKeys, Matchers.notNullValue());

        final PGPPublicKey pgpPublicKey = PGPUtilities.extractSigningPublicKey(publicKeys);
        assertThat(pgpPublicKey, Matchers.notNullValue());
        assertThat(pgpPublicKey.getKeyID(), equalTo(ExampleMessages.PUBKEY_SENDER_2));
    }


    @Test()
    public void findingUnknownPrivateKey_returnsNull() throws Exception {

        final PGPSecretKeyRingCollection secretKeyRings = keyringConfig.getSecretKeyRings();

        final PGPPrivateKey privateKey = PGPUtilities.findSecretKey(secretKeyRings, PRIVATE_KEY_ID__ONLY_HAVE_PUB_KEY, PRIVATE_MASTER_KEY_RECIPIENT_PASSPHRASE);
        assertThat(privateKey, Matchers.nullValue());
    }


    @Test()
    public void findingPrivateMasterKey_withGoodPassword_returnsKey() throws Exception {

        final PGPSecretKeyRingCollection secretKeyRings = keyringConfig.getSecretKeyRings();
        final PGPPrivateKey pgpPrivateKey = PGPUtilities.findSecretKey(secretKeyRings, PRIVATE_MASTER_KEY_RECIPIENT, PRIVATE_MASTER_KEY_RECIPIENT_PASSPHRASE);

        assertThat(pgpPrivateKey, Matchers.notNullValue());
    }

    @Test()
    public void extractingPrivateMasterKey_withGoodPassword_returnsKey() throws Exception {

        final PGPSecretKeyRingCollection secretKeyRings = keyringConfig.getSecretKeyRings();

        final PGPSecretKey secretKey = secretKeyRings.getSecretKey(PRIVATE_MASTER_KEY_RECIPIENT);
        assumeNotNull(secretKey);

        final PGPPrivateKey pgpPrivateKey = PGPUtilities.extractPrivateKey(secretKey, PRIVATE_MASTER_KEY_RECIPIENT_PASSPHRASE);

        assertThat(pgpPrivateKey, Matchers.notNullValue());
    }

    @Test()
    public void extractingPrivateSubKey_withGoodPassword_returnsKey() throws Exception {

        final PGPSecretKeyRingCollection secretKeyRings = keyringConfig.getSecretKeyRings();
        final PGPPrivateKey pgpPrivateKey = PGPUtilities.extractPrivateKey(secretKeyRings.getSecretKey(PRIVATE_SUB_KEY_RECIPIENT), PRIVATE_MASTER_KEY_RECIPIENT_PASSPHRASE);

        assertThat(pgpPrivateKey, Matchers.notNullValue());
    }

    @Test(expected = PGPException.class)
    public void extractingPrivateKey_withWrongPassword_throws() throws Exception {

        final PGPSecretKeyRingCollection secretKeyRings = keyringConfig.getSecretKeyRings();

        PGPUtilities.extractPrivateKey(secretKeyRings.getSecretKey(PRIVATE_SUB_KEY_RECIPIENT), "wrong password".toCharArray());
    }

}
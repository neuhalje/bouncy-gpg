package name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.hamcrest.text.IsEmptyString;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.security.Security;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class DecryptionConfigTest {
    @Before
    public void before() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }


    /*
     * make sure that the tests work independently of the way the config has been created
     */
    @Parameterized.Parameters
    public static Object[] data() {
        return new Object[]{Configs.buildConfigForDecryptionFromResources(), Configs.buildConfigForDecryptionFromFiles()};
    }


    @Parameterized.Parameter
    public /* NOT private */ DecryptionConfig decryptionConfig;

    @Test
    public void toString_returns_nonEmptyString() throws Exception {
        assertThat(decryptionConfig.toString(), is(not(IsEmptyString.isEmptyString())));
    }

    @Test
    public void getKeyFingerPrintCalculator_returnsNonNull() throws IOException, PGPException {
        assertNotNull(decryptionConfig.getKeyFingerPrintCalculator());
    }

    @Test
    public void doesNotThrow() throws IOException, PGPException {
        assertThat(decryptionConfig.getPublicKeyRings(), is(notNullValue()));
        assertThat(decryptionConfig.getSecretKeyRings(), is(notNullValue()));
    }

    @Test
    public void loading_doesNotThrow() throws IOException, PGPException {
        assertThat(decryptionConfig.getPublicKeyRings(), is(notNullValue()));
        assertThat(decryptionConfig.getSecretKeyRings(), is(notNullValue()));
    }

    @Test
    public void findPubKeys_works() throws IOException, PGPException {
        assertTrue(decryptionConfig.getPublicKeyRings().contains(ExampleMessages.PUBKEY_SENDER));
        assertTrue(decryptionConfig.getPublicKeyRings().contains(ExampleMessages.PUBKEY_SENDER_2));
        assertTrue(decryptionConfig.getPublicKeyRings().contains(ExampleMessages.PUBKEY_RECIPIENT));
    }


    @Test
    public void findSecretKey_works() throws IOException, PGPException {
        assertTrue(decryptionConfig.getSecretKeyRings().contains(ExampleMessages.SECRETKEY_RECIPIENT));
    }

}
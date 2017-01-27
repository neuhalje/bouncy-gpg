package name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import org.hamcrest.text.IsEmptyString;
import org.junit.Test;

import java.io.IOException;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;


public class DecryptionConfigTest {
    @Test
    public void toString_returns_nonEmptyString() throws Exception {
        final DecryptionConfig decryptionConfig = Configs.buildConfigForDecryptionFromResources();
        assertThat(decryptionConfig.toString(), is(not(IsEmptyString.isEmptyString())));
    }

    @Test
    public void loadFromFiles_works() throws IOException {
        final DecryptionConfig decryptionConfig = Configs.buildConfigForDecryptionFromFiles();
        assertThat(decryptionConfig.getPublicKeyRing(), is(notNullValue()));
        assertThat(decryptionConfig.getSecretKeyRing(), is(notNullValue()));
    }

}
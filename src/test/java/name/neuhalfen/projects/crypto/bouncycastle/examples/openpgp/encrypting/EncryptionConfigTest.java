package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.testtooling.Configs;
import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.hamcrest.text.IsEmptyString;
import org.junit.Test;

import java.io.IOException;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;


public class EncryptionConfigTest {
    @Test
    public void toString_returns_nonEmptyString() throws Exception {
        final EncryptionConfig encryptionConfig = Configs.buildConfigForEncryptionFromResources();
        assertThat(encryptionConfig.toString(), is(not(IsEmptyString.isEmptyString())));
    }

    @Test
    public void loadFromFiles_works() throws IOException {
        final EncryptionConfig encryptionConfig = Configs.buildConfigForEncryptionFromFiles();

        assertThat(encryptionConfig.getEncryptionPublicKeyId(), is(not(isEmptyOrNullString())));
        assertThat(encryptionConfig.getPgpHashAlgorithmCode(), is(not(equalTo((int) HashAlgorithm.none))));

        assertThat(encryptionConfig.getPublicKeyRing(), is(notNullValue()));
        assertThat(encryptionConfig.getSecretKeyRing(), is(notNullValue()));
    }

}
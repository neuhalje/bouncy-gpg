package name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting.keyrings;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting.EncryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.openpgp.PGPException;
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
    public void loadFromFiles_works() throws IOException, PGPException {
        final EncryptionConfig encryptionConfig = Configs.buildConfigForEncryptionFromFiles(KeyringConfigCallbacks.withUnprotectedKeys());

        assertThat(encryptionConfig.getEncryptionPublicKeyId(), is(not(isEmptyOrNullString())));
        assertThat(encryptionConfig.getPgpHashAlgorithmCode(), is(not(equalTo((int) HashAlgorithm.none))));

        assertThat(encryptionConfig.getPublicKeyRings(), is(notNullValue()));
        assertThat(encryptionConfig.getSecretKeyRings(), is(notNullValue()));
    }

}
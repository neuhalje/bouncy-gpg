package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import org.junit.Test;

import static org.junit.Assert.assertNotNull;


public class BouncyGPGTest {
    @Test
    public void decrypt_notNull() throws Exception {
        assertNotNull(BouncyGPG.decrypt());
    }

    @Test
    public void encryptToStream_notNull() throws Exception {
        assertNotNull(BouncyGPG.encryptToStream());
    }

    @Test
    public void verifySignature_notNull() throws Exception {
        assertNotNull(BouncyGPG.verifySignature());
    }
}
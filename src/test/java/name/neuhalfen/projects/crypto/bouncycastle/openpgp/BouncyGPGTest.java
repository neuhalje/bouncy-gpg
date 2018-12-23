package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;


public class BouncyGPGTest {

  @Test
  public void decrypt_notNull() throws Exception {
    assertNotNull(BouncyGPG.decryptAndVerifyStream());
  }

  @Test
  public void encryptToStream_notNull() throws Exception {
    assertNotNull(BouncyGPG.encryptToStream());
  }

  @Test
  public void createKeyring_notNull() throws Exception {
    assertNotNull(BouncyGPG.createKeyring());
  }
}
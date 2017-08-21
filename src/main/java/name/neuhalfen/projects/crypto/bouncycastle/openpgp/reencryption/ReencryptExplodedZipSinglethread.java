package name.neuhalfen.projects.crypto.bouncycastle.openpgp.reencryption;

import java.io.InputStream;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BuildEncryptionOutputStreamAPI;

/**
 * @see ReencryptExplodedZipSinglethread
 */
public final class ReencryptExplodedZipSinglethread {


  public void explodeAndReencrypt(InputStream plainTextStream, ZipEntityStrategy zipEntityStrategy,
      BuildEncryptionOutputStreamAPI.Build encryptionFactory) throws Exception {

    final ExplodeAndReencrypt explodeAndReencrypt = new ExplodeAndReencrypt(
        zipEntityStrategy, encryptionFactory);
    explodeAndReencrypt.explodeAndReencrypt(plainTextStream);
  }
}


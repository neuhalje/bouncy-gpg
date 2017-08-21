package name.neuhalfen.projects.crypto.bouncycastle.openpgp.reencryption;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BuildEncryptionOutputStreamAPI;
import org.bouncycastle.openpgp.PGPException;

/**
 * @see ReencryptExplodedZipSinglethread
 */
public final class ReencryptExplodedZipSinglethread {


  public void explodeAndReencrypt(InputStream plainTextStream, ZipEntityStrategy zipEntityStrategy,
      BuildEncryptionOutputStreamAPI.Build encryptionFactory)
      throws NoSuchAlgorithmException, PGPException, SignatureException, NoSuchProviderException, IOException {

    final ExplodeAndReencrypt explodeAndReencrypt = new ExplodeAndReencrypt(
        zipEntityStrategy, encryptionFactory);
    explodeAndReencrypt.explodeAndReencrypt(plainTextStream);
  }
}


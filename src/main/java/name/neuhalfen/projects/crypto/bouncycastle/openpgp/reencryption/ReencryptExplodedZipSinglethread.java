package name.neuhalfen.projects.crypto.bouncycastle.openpgp.reencryption;

import static java.util.Objects.requireNonNull;

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

  public ReencryptExplodedZipSinglethread() {
    // nothing to do
  }

  public void explodeAndReencrypt(InputStream plainTextStream, ZipEntityStrategy zipEntityStrategy,
      BuildEncryptionOutputStreamAPI.Build encryptionFactory)
      throws NoSuchAlgorithmException, PGPException, SignatureException, NoSuchProviderException, IOException {

    requireNonNull(plainTextStream, "plainTextStream must not be null");
    requireNonNull(zipEntityStrategy, "zipEntityStrategy must not be null");
    requireNonNull(encryptionFactory, "encryptionFactory must not be null");

    final ExplodeAndReencrypt explodeAndReencrypt = new ExplodeAndReencrypt(
        zipEntityStrategy, encryptionFactory);
    explodeAndReencrypt.explodeAndReencrypt(plainTextStream);
  }
}


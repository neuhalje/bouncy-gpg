package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public interface StreamDecryption {

    void decryptAndVerify(final InputStream is, final OutputStream os) throws IOException, SignatureException;
}

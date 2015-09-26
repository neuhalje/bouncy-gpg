package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public interface StreamEncryption {

    void encryptAndSign(final InputStream is, final OutputStream os) throws IOException, NoSuchAlgorithmException, SignatureException;
}

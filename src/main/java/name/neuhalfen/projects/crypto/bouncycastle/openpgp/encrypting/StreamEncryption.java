package name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting;


import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

public interface StreamEncryption {

    /**
     * Encrypts and signs. The implementing class will make sure that the data available in 'is' gets
     * encrypted and written to 'os'.
     *
     * @param is Input -- must be closed by caller!
     * @param os Output -- must be closed by caller!
     * @throws IOException IO is ugly
     * @throws NoSuchAlgorithmException Cannot encrypt
     * @throws SignatureException Cannot sign
     * @throws PGPException general PGP problem
     *
     */
    void encryptAndSign(final InputStream is, final OutputStream os) throws IOException,
            NoSuchAlgorithmException,
            SignatureException, PGPException, NoSuchProviderException;
}

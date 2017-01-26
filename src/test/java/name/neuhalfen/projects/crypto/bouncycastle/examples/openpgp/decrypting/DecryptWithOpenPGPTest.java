package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SignatureException;


public class DecryptWithOpenPGPTest extends DecryptBaseTest {

    @Override
    String decrypt(byte[] encrypted, DecryptionConfig config) throws IOException, SignatureException {
        DecryptWithOpenPGP sut = new DecryptWithOpenPGP(config);

        ByteArrayOutputStream res = new ByteArrayOutputStream();
        sut.decryptAndVerify(new ByteArrayInputStream(encrypted), res);

        res.close();

        String decryptedQuote = res.toString("UTF-8");
        return decryptedQuote;
    }
}
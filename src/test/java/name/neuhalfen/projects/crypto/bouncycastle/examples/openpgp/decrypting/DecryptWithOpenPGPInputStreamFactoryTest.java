package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting;

import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class DecryptWithOpenPGPInputStreamFactoryTest extends DecryptBaseTest {


    @Override
    String decrpyt(byte[] encrypted, DecryptionConfig config) throws IOException {
        final DecryptWithOpenPGPInputStreamFactory sut = DecryptWithOpenPGPInputStreamFactory.create(config);

        final InputStream plainTextInputStream = sut.wrapWithDecryptAndVerify(new ByteArrayInputStream(encrypted));

        ByteArrayOutputStream res = new ByteArrayOutputStream();
        Streams.pipeAll(plainTextInputStream, res);
        res.close();
        plainTextInputStream.close();

        String decrypted = res.toString("US-ASCII");
        return decrypted;
    }
}
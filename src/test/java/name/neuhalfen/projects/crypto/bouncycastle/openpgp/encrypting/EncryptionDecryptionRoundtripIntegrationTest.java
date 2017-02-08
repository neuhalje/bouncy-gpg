package name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;

import static org.junit.Assert.assertArrayEquals;

public class EncryptionDecryptionRoundtripIntegrationTest {

    @Before
    public void installBCProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void encryptAndSign_thenDecryptAndVerify_yieldsOriginalPlaintext() throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        StreamEncryption encrypt = new EncryptWithOpenPGP(Configs.buildConfigForEncryptionFromResources());

        final byte[] expectedPlaintext = ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes("US-ASCII");
        ByteArrayInputStream plainTextSource = new ByteArrayInputStream(expectedPlaintext);
        ByteArrayOutputStream cipherText = new ByteArrayOutputStream();

        encrypt.encryptAndSign(plainTextSource, cipherText);
        cipherText.flush();
        cipherText.close();

        final byte[] byteArray = cipherText.toByteArray();
        ByteArrayInputStream cipherTextAsSource = new ByteArrayInputStream(byteArray);
        // Decrypt
        final InputStream decryptedPlaintextStream = BouncyGPG.decryptAndVerifyStream().withConfig(Configs.keyringConfigFromResourceForRecipient()).andRequireSignatureFromAllKeys("sender@example.com").fromEncryptedInputStream(cipherTextAsSource);
        final byte[] decryptedPlaintext = Streams.readAll(decryptedPlaintextStream);

        assertArrayEquals(expectedPlaintext, decryptedPlaintext);
    }
}

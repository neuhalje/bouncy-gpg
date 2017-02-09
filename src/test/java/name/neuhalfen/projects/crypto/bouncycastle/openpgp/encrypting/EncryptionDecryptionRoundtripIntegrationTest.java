package name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;
import org.junit.Before;
import org.junit.Test;

import java.io.*;
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
    public void encryptAndSignArmored_thenDecryptAndVerify_yieldsOriginalPlaintext() throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        final byte[] expectedPlaintext = ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes("US-ASCII");

        ByteArrayOutputStream cipherText = new ByteArrayOutputStream();

        final OutputStream encryptionStream = BouncyGPG
                .encryptToStream()
                .withConfig(Configs.keyringConfigFromFilesForSender())
                .withDefaultAlgorithms()
                .toRecipient("recipient@example.com")
                .andSignWith("sender@example.com")
                .armorAsciiOutput()
                .andWriteTo(cipherText);

        encryptionStream.write(expectedPlaintext);
        encryptionStream.close();
        cipherText.close();

        ByteArrayInputStream cipherTextAsSource = new ByteArrayInputStream(cipherText.toByteArray());

        // Decrypt
        final InputStream decryptedPlaintextStream = BouncyGPG
                .decryptAndVerifyStream()
                .withConfig(Configs.keyringConfigFromResourceForRecipient())
                .andRequireSignatureFromAllKeys("sender@example.com")
                .fromEncryptedInputStream(cipherTextAsSource);

        final byte[] decryptedPlaintext = Streams.readAll(decryptedPlaintextStream);

        assertArrayEquals(expectedPlaintext, decryptedPlaintext);
    }


    @Test
    public void encryptAndSignBinary_thenDecryptAndVerify_yieldsOriginalPlaintext() throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        final byte[] expectedPlaintext = ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes("US-ASCII");

        ByteArrayOutputStream cipherText = new ByteArrayOutputStream();

        final OutputStream encryptionStream = BouncyGPG
                .encryptToStream()
                .withConfig(Configs.keyringConfigFromFilesForSender())
                .withDefaultAlgorithms()
                .toRecipient("recipient@example.com")
                .andSignWith("sender@example.com")
                .binaryOutput()
                .andWriteTo(cipherText);

        encryptionStream.write(expectedPlaintext);
        encryptionStream.close();
        cipherText.close();

        ByteArrayInputStream cipherTextAsSource = new ByteArrayInputStream(cipherText.toByteArray());

        // Decrypt
        final InputStream decryptedPlaintextStream = BouncyGPG
                .decryptAndVerifyStream()
                .withConfig(Configs.keyringConfigFromResourceForRecipient())
                .andRequireSignatureFromAllKeys("sender@example.com")
                .fromEncryptedInputStream(cipherTextAsSource);

        final byte[] decryptedPlaintext = Streams.readAll(decryptedPlaintextStream);

        assertArrayEquals(expectedPlaintext, decryptedPlaintext);
    }


    @Test
    public void encryptAndSignWithDSA_thenDecryptAndVerify_yieldsOriginalPlaintext() throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        final byte[] expectedPlaintext = ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes("US-ASCII");

        ByteArrayOutputStream cipherText = new ByteArrayOutputStream();

        final OutputStream encryptionStream = BouncyGPG
                .encryptToStream()
                .withConfig(Configs.keyringConfigFromFilesForSender())
                .withDefaultAlgorithms()
                .toRecipient("recipient@example.com")
                .andSignWith("sender.signonly@example.com")
                .binaryOutput()
                .andWriteTo(cipherText);

        encryptionStream.write(expectedPlaintext);
        encryptionStream.close();
        cipherText.close();

        ByteArrayInputStream cipherTextAsSource = new ByteArrayInputStream(cipherText.toByteArray());

        // Decrypt
        final InputStream decryptedPlaintextStream = BouncyGPG
                .decryptAndVerifyStream()
                .withConfig(Configs.keyringConfigFromResourceForRecipient())
                .andRequireSignatureFromAllKeys("sender.signonly@example.com")
                .fromEncryptedInputStream(cipherTextAsSource);

        final byte[] decryptedPlaintext = Streams.readAll(decryptedPlaintextStream);

        assertArrayEquals(expectedPlaintext, decryptedPlaintext);
    }
}

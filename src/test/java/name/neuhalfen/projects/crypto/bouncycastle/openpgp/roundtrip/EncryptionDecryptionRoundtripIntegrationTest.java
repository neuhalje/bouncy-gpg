package name.neuhalfen.projects.crypto.bouncycastle.openpgp.roundtrip;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.*;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;

import static org.junit.Assert.assertArrayEquals;

@RunWith(Parameterized.class)
public class EncryptionDecryptionRoundtripIntegrationTest {


    /*
     * make sure that the tests work independently of the way the config has been created
     */
    @Parameterized.Parameters
    public static Object[] data() {
        return new Object[]{DefaultPGPAlgorithmSuites.defaultSuiteForGnuPG(),
                DefaultPGPAlgorithmSuites.strongSuite()};
    }


    @Parameterized.Parameter
    public /* NOT private */ PGPAlgorithmSuite algorithmSuite;


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
                .withAlgorithms(algorithmSuite)
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
                .withAlgorithms(algorithmSuite)
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
    public void encryptAndSignBinaryWithSHA256_AES256_thenDecryptAndVerify_yieldsOriginalPlaintext() throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        final byte[] expectedPlaintext = ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes("US-ASCII");

        ByteArrayOutputStream cipherText = new ByteArrayOutputStream();

        final OutputStream encryptionStream = BouncyGPG
                .encryptToStream()
                .withConfig(Configs.keyringConfigFromFilesForSender())
                .withAlgorithms(new PGPAlgorithmSuite(PGPHashAlgorithms.SHA_256, PGPSymmetricEncryptionAlgorithms.AES_256, PGPCompressionAlgorithms.BZIP2))
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
                .withAlgorithms(algorithmSuite)
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


    @Test
    public void encryptBinary_thenDecrypt_yieldsOriginalPlaintext() throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        final byte[] expectedPlaintext = ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes("US-ASCII");

        ByteArrayOutputStream cipherText = new ByteArrayOutputStream();

        final OutputStream encryptionStream = BouncyGPG
                .encryptToStream()
                .withConfig(Configs.keyringConfigFromFilesForSender())
                .withAlgorithms(algorithmSuite)
                .toRecipient("recipient@example.com")
                .andDoNotSign()
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
                .andIgnoreSignatures()
                .fromEncryptedInputStream(cipherTextAsSource);

        final byte[] decryptedPlaintext = Streams.readAll(decryptedPlaintextStream);

        assertArrayEquals(expectedPlaintext, decryptedPlaintext);
    }


}

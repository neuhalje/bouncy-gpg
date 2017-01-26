package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.testtooling.Configs;
import org.bouncycastle.util.io.Streams;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import static name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.testtooling.ExampleMessages.*;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.mockito.Mockito.*;

/**
 * All decryption schemes must adhere to the same basic rules regarding crypto.
 */
abstract class DecryptBaseTest {

    @Test
    public void decrypting_anyData_doesNotCloseInputStream() throws IOException, SignatureException, NoSuchAlgorithmException {

        final DecryptWithOpenPGPInputStreamFactory sut = DecryptWithOpenPGPInputStreamFactory.create(Configs.buildConfigForDecryptionFromResources());

        InputStream in = spy(new ByteArrayInputStream(IMPORTANT_QUOTE_COMPRESSED.getBytes("US-ASCII")));

        final InputStream decryptAndVerify = sut.wrapWithDecryptAndVerify(in);
        decryptAndVerify.close();

        verify(in, never()).close();
    }


    @Test
    public void decryptingAndVerifying_smallAmountsOfData_correctlyDecryptsUncompressedAndArmored() throws IOException, SignatureException, NoSuchAlgorithmException {
        final DecryptionConfig config = Configs.buildConfigForDecryptionFromResources();

        String decryptedQuote = decrypt(IMPORTANT_QUOTE_NOT_COMPRESSED.getBytes("US-ASCII"), config);
        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    @Test
    public void decryptingAndVerifying_smallAmountsOfData_correctlyDecryptsCompressedAndArmored() throws IOException, SignatureException, NoSuchAlgorithmException {

        final DecryptionConfig config = Configs.buildConfigForDecryptionFromResources();

        String decryptedQuote = decrypt(IMPORTANT_QUOTE_COMPRESSED.getBytes("US-ASCII"), config);
        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    @Test(expected = IOException.class)
    public void decryptingTamperedCiphertext_fails() throws IOException, NoSuchAlgorithmException {

        final DecryptWithOpenPGPInputStreamFactory sut = DecryptWithOpenPGPInputStreamFactory.create(Configs.buildConfigForDecryptionFromResources());

        byte[] buf = IMPORTANT_QUOTE_NOT_COMPRESSED.getBytes("US-ASCII");

        // tamper
        buf[666]++;

        final InputStream plainTextInputStream = sut.wrapWithDecryptAndVerify(new ByteArrayInputStream(buf));

        Streams.drain(plainTextInputStream);
    }

    @Test(expected = IOException.class)
    public void decryptingMessage_withoutHavingSecretKey_fails() throws IOException, SignatureException {
        final DecryptionConfig config = Configs.buildConfigForDecryptionFromResources(false);

        decrypt(IMPORTANT_QUOTE_NOT_ENCRYPTED_TO_ME.getBytes("US-ASCII"), config);
    }

    @Test(expected = IOException.class)
    public void decryptingUnsignedMessage_butSignatureIsRequired_fails() throws IOException, SignatureException {
        final DecryptionConfig config = Configs.buildConfigForDecryptionFromResources(true);

        final String decryptedQuote = decrypt(IMPORTANT_QUOTE_NOT_SIGNED.getBytes("US-ASCII"), config);

        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    @Test
    public void decryptingUnsignedMessage_butSignatureIsNotRequired_succeeds() throws IOException, SignatureException {
        final DecryptionConfig config = Configs.buildConfigForDecryptionFromResources(false);

        final String decryptedQuote = decrypt(IMPORTANT_QUOTE_NOT_SIGNED.getBytes("US-ASCII"), config);

        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    @Test
    public void decryptingSignedMessage_butSignatureIsNotRequired_succeeds() throws IOException, SignatureException {
        final DecryptionConfig config = Configs.buildConfigForDecryptionFromResources(false);

        final String decryptedQuote = decrypt(IMPORTANT_QUOTE_COMPRESSED.getBytes("US-ASCII"), config);

        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    abstract String decrypt(byte[] encrypted, DecryptionConfig config) throws IOException, SignatureException;
}
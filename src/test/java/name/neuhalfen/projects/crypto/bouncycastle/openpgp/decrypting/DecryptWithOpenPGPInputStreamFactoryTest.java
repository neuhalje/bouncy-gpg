package name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationStrategies;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationStrategy;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages.*;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.*;

public class DecryptWithOpenPGPInputStreamFactoryTest {

    String decrypt(byte[] encrypted, KeyringConfig config, SignatureValidationStrategy signatureValidationStrategy) throws IOException {
        final DecryptWithOpenPGPInputStreamFactory sut = DecryptWithOpenPGPInputStreamFactory.create(config, signatureValidationStrategy);

        final InputStream plainTextInputStream;
        try {
            plainTextInputStream = sut.wrapWithDecryptAndVerify(new ByteArrayInputStream(encrypted));
        } catch (NoSuchProviderException e) {
            assertTrue("BC provider must be registered by test", false);
            throw new AssertionError(e);
        }

        ByteArrayOutputStream res = new ByteArrayOutputStream();
        Streams.pipeAll(plainTextInputStream, res);
        res.close();
        plainTextInputStream.close();

        String decrypted = res.toString("US-ASCII");
        return decrypted;
    }

    @Test
    public void decrypting_anyData_doesNotCloseInputStream() throws IOException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {

        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();
        final DecryptWithOpenPGPInputStreamFactory sut = DecryptWithOpenPGPInputStreamFactory.create(config, SignatureValidationStrategies.ignoreSignatures());

        InputStream in = spy(new ByteArrayInputStream(IMPORTANT_QUOTE_SIGNED_COMPRESSED.getBytes("US-ASCII")));

        final InputStream decryptAndVerify = sut.wrapWithDecryptAndVerify(in);
        decryptAndVerify.close();

        verify(in, never()).close();
    }


    @Test
    public void decryptingAndVerifying_smallAmountsOfData_correctlyDecryptsUncompressedAndArmored() throws IOException, SignatureException, NoSuchAlgorithmException {
        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        String decryptedQuote = decrypt(IMPORTANT_QUOTE_SIGNED_NOT_COMPRESSED.getBytes("US-ASCII"), config, SignatureValidationStrategies.ignoreSignatures());
        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    @Test
    public void decryptingAndVerifyingMessageWith_Single_Signature_requiringAnySignature_correctlyDecryptsCompressedAndArmored() throws IOException, SignatureException, NoSuchAlgorithmException {

        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        String decryptedQuote = decrypt(IMPORTANT_QUOTE_SIGNED_COMPRESSED.getBytes("US-ASCII"), config, SignatureValidationStrategies.requireAnySignature());
        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    @Test
    public void decryptingAndVerifyingMessageWith_SingleUnknown_Signature_requiringNoSignature_correctlyDecryptsCompressedAndArmored() throws IOException, SignatureException, NoSuchAlgorithmException {

        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        String decryptedQuote = decrypt(IMPORTANT_QUOTE_SIGNED_UNKNOWN_KEY_COMPRESSED.getBytes("US-ASCII"), config, SignatureValidationStrategies.ignoreSignatures());
        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    @Test(expected = IOException.class)
    public void decryptingAndVerifyingMessageWith_SingleUnknown_Signature_requiringAnySignature_correctlyDecryptsCompressedAndArmored() throws IOException, SignatureException, NoSuchAlgorithmException {

        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        decrypt(IMPORTANT_QUOTE_SIGNED_UNKNOWN_KEY_COMPRESSED.getBytes("US-ASCII"), config, SignatureValidationStrategies.requireAnySignature());
    }

    @Test
    public void decryptingAndVerifyingMessageWith_Multiple_Signatures_requiringNoSignature_correctlyDecryptsCompressedAndArmored() throws IOException, SignatureException, NoSuchAlgorithmException {
        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        final String decryptedQuote = decrypt(IMPORTANT_QUOTE_SIGNED_MULTIPLE_COMPRESSED.getBytes("US-ASCII"), config, SignatureValidationStrategies.ignoreSignatures());

        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    @Test(expected = IOException.class)
    public void decryptingTamperedSignedCiphertext_fails() throws IOException, NoSuchAlgorithmException, NoSuchProviderException {

        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();
        final DecryptWithOpenPGPInputStreamFactory sut = DecryptWithOpenPGPInputStreamFactory.create(config, SignatureValidationStrategies.requireAnySignature());

        byte[] buf = IMPORTANT_QUOTE_SIGNED_NOT_COMPRESSED.getBytes("US-ASCII");

        // tamper
        buf[666]++;

        final InputStream plainTextInputStream = sut.wrapWithDecryptAndVerify(new ByteArrayInputStream(buf));

        Streams.drain(plainTextInputStream);
    }

    @Test(expected = IOException.class)
    public void decryptingSignedMessageAndRequiringSpecificSigner_notSignedByTheCorrectKey_fails() throws IOException, SignatureException, NoSuchAlgorithmException {
        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        decrypt(IMPORTANT_QUOTE_SIGNED_COMPRESSED.getBytes("US-ASCII"), config, SignatureValidationStrategies.requireSignatureFromAllKeys(ExampleMessages.PUBKEY_RECIPIENT));
    }

    @Test(expected = IOException.class)
    public void decryptingMultiSignedMessageAndRequiringSpecificSigner_notSignedByTheCorrectKey_fails() throws IOException, SignatureException, NoSuchAlgorithmException {
        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        decrypt(IMPORTANT_QUOTE_SIGNED_MULTIPLE_COMPRESSED.getBytes("US-ASCII"), config, SignatureValidationStrategies.requireSignatureFromAllKeys(ExampleMessages.PUBKEY_RECIPIENT));
    }

    @Test
    public void decryptingSignedMessageAndRequiringSpecificSigner_signedByTheCorrectKey_succeeds() throws IOException, SignatureException, NoSuchAlgorithmException {
        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        final String decryptedQuote = decrypt(IMPORTANT_QUOTE_SIGNED_COMPRESSED.getBytes("US-ASCII"), config, SignatureValidationStrategies.requireSignatureFromAllKeys(ExampleMessages.PUBKEY_SENDER));

        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    @Test(expected = IOException.class)
    public void decryptingSignedMessageAndRequiringMultipleSpecificSigner_signedBySubsetOfTheCorrectKeys_fails() throws IOException, SignatureException, NoSuchAlgorithmException {
        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        decrypt(IMPORTANT_QUOTE_SIGNED_MULTIPLE_V2_COMPRESSED.getBytes("US-ASCII"), config, SignatureValidationStrategies.requireSignatureFromAllKeys(ExampleMessages.PUBKEY_SENDER, ExampleMessages.PUBKEY_ANOTHER_SENDER));
    }

    @Test
    public void decryptingSignedMessageAndRequiringMultipleSpecificSigner_signedByTheCorrectKeys_succeeds() throws IOException, SignatureException, NoSuchAlgorithmException {
        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        final String decryptedQuote = decrypt(IMPORTANT_QUOTE_SIGNED_BY_2_KNOWN_1_UNKNOWN_KEY.getBytes("US-ASCII"), config, SignatureValidationStrategies.requireSignatureFromAllKeys(ExampleMessages.PUBKEY_SENDER, ExampleMessages.PUBKEY_SENDER_2));

        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    @Test
    public void usingSingleUserIdToSignatureValidationSelectKeys_isResolvable_verificationSucceeds() throws IOException, SignatureException, NoSuchAlgorithmException, PGPException {
        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        final String decryptedQuote = decrypt(IMPORTANT_QUOTE_SIGNED_MULTIPLE_COMPRESSED.getBytes("US-ASCII"), config, SignatureValidationStrategies.requireSignatureFromAllKeys(config.getPublicKeyRings(), "sender@example.com"));

        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    @Test
    public void usingUserIdsToSignatureValidationSelectKeys_allKeysResolvable_verificationSucceeds() throws IOException, SignatureException, NoSuchAlgorithmException, PGPException {
        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        final String decryptedQuote = decrypt(IMPORTANT_QUOTE_SIGNED_BY_2_KNOWN_1_UNKNOWN_KEY.getBytes("US-ASCII"), config, SignatureValidationStrategies.requireSignatureFromAllKeys(config.getPublicKeyRings(), "sender@example.com", "sender2@example.com"));

        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    @Test(expected = PGPException.class)
    public void usingUserIdsToSignatureValidationSelectKeys_oneKeyNotResolvable_fails() throws IOException, SignatureException, NoSuchAlgorithmException, PGPException {
        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        SignatureValidationStrategies.requireSignatureFromAllKeys(config.getPublicKeyRings(), "sender@example.com", "unknown@example.com");
    }

    @Test
    public void decryptingSignedMessageAndRequiringSpecificSigner_signedByTheCorrectKeyAndOthers_succeeds() throws IOException, SignatureException, NoSuchAlgorithmException {
        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        final String decryptedQuote = decrypt(IMPORTANT_QUOTE_SIGNED_MULTIPLE_COMPRESSED.getBytes("US-ASCII"), config, SignatureValidationStrategies.requireSignatureFromAllKeys(ExampleMessages.PUBKEY_SENDER));

        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    @Test(expected = IOException.class)
    public void decryptingMessage_withoutHavingSecretKey_fails() throws IOException, SignatureException {
        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        decrypt(IMPORTANT_QUOTE_NOT_ENCRYPTED_TO_ME.getBytes("US-ASCII"), config, SignatureValidationStrategies.ignoreSignatures());
    }

    @Test(expected = IOException.class)
    public void decryptingUnsignedMessage_butAnySignatureIsRequired_fails() throws IOException, SignatureException {
        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        final String decryptedQuote = decrypt(IMPORTANT_QUOTE_NOT_SIGNED_NOT_COMPRESSED.getBytes("US-ASCII"), config, SignatureValidationStrategies.requireAnySignature());

        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    @Test(expected = IOException.class)
    public void decryptingUnsignedMessage_butSpecificSignatureIsRequired_fails() throws IOException, SignatureException {
        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        final String decryptedQuote = decrypt(IMPORTANT_QUOTE_NOT_SIGNED_NOT_COMPRESSED.getBytes("US-ASCII"), config, SignatureValidationStrategies.requireSignatureFromAllKeys(ExampleMessages.PUBKEY_SENDER));

        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    @Test
    public void decryptingUnsignedMessage_andSignatureIsNotRequired_succeeds() throws IOException, SignatureException {
        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        final String decryptedQuote = decrypt(IMPORTANT_QUOTE_NOT_SIGNED_NOT_COMPRESSED.getBytes("US-ASCII"), config, SignatureValidationStrategies.ignoreSignatures());

        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    @Test
    public void decryptingSignedMessage_andSignatureIsNotRequired_succeeds() throws IOException, SignatureException {
        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        final String decryptedQuote = decrypt(IMPORTANT_QUOTE_SIGNED_COMPRESSED.getBytes("US-ASCII"), config, SignatureValidationStrategies.ignoreSignatures());

        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    @Test
    public void decryptingSignedMessageWithSingleeSignatures_andAnySignatureIsRequired_succeeds() throws IOException, SignatureException {
        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        final String decryptedQuote = decrypt(IMPORTANT_QUOTE_SIGNED_COMPRESSED.getBytes("US-ASCII"), config, SignatureValidationStrategies.requireAnySignature());

        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    @Test
    public void decryptingSignedMessageWithMultipleSignaturesKnownSignatureFirst_andAnySignatureIsRequired_succeeds() throws IOException, SignatureException {
        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        final String decryptedQuote = decrypt(IMPORTANT_QUOTE_SIGNED_MULTIPLE_COMPRESSED.getBytes("US-ASCII"), config, SignatureValidationStrategies.requireAnySignature());

        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

    @Test
    public void decryptingSignedMessageWithMultipleSignaturesUnknownSignatureFirst_andAnySignatureIsRequired_succeeds() throws IOException, SignatureException {
        final KeyringConfig config = Configs.keyringConfigFromFilesForRecipient();

        final String decryptedQuote = decrypt(IMPORTANT_QUOTE_SIGNED_MULTIPLE_V2_COMPRESSED.getBytes("US-ASCII"), config, SignatureValidationStrategies.requireAnySignature());

        Assert.assertThat(decryptedQuote, equalTo(IMPORTANT_QUOTE_TEXT));
    }

}
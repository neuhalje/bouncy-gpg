package name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.DefaultPGPAlgorithmSuites;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;
import org.junit.Test;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.time.Instant;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Tests several encryption scenarios. As usual, most are integration style tests.
 */
public class EncryptionScenariosTest {

    @Test
    public void encrypt_masterKeyWithoutSubkeys_works()
            throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {

        // Reported in  https://github.com/neuhalje/bouncy-gpg/issues/34

        // keyring
        InMemoryKeyring sendersKeyring = KeyringConfigs.forGpgExportedKeys(keyId -> null);
        sendersKeyring.addPublicKey(ExampleMessages.ONLY_MASTER_KEY_PUBKEY.getBytes());

        InMemoryKeyring recipientsKeyring = KeyringConfigs.forGpgExportedKeys(keyId -> null);
        recipientsKeyring.addSecretKey(ExampleMessages.ONLY_MASTER_KEY_PRIVKEY.getBytes());

        // encrypt
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(result);

        final OutputStream outputStream = BouncyGPG
                .encryptToStream()
                .withConfig(sendersKeyring)
                .setReferenceDateForKeyValidityTo(Instant.MAX)
                .withAlgorithms(DefaultPGPAlgorithmSuites.strongSuite())
                .toRecipient(ExampleMessages.ONLY_MASTER_KEY_UID)
                .andDoNotSign()
                .binaryOutput()
                .andWriteTo(bufferedOutputStream);

        final InputStream is = new ByteArrayInputStream(
                ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes());
        Streams.pipeAll(is, outputStream);
        outputStream.close();
        bufferedOutputStream.close();
        is.close();

        // test decryption

        final byte[] ciphertext = result.toByteArray();
        result.close();
        final ByteArrayOutputStream plainBA = new ByteArrayOutputStream();

        final InputStream plainIS = BouncyGPG.decryptAndVerifyStream()
                .withConfig(recipientsKeyring)
                .andIgnoreSignatures()
                .fromEncryptedInputStream(new ByteArrayInputStream(ciphertext));

        Streams.pipeAll(plainIS, plainBA);

        assertArrayEquals(ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes(), plainBA.toByteArray());
    }

    @Test
    public void encrypt_masterKeyWithoutSubkeysOrKeyFlags_works()
            throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {

        // Reported in  https://github.com/neuhalje/bouncy-gpg/issues/50

        /* We test that a key that doesn't contain any KeyFlags subpacket can still be used for encrypting,
        by checking the key algorithm, like GPG does
         */

        // keyring
        InMemoryKeyring sendersKeyring = KeyringConfigs.forGpgExportedKeys(keyId -> null);
        sendersKeyring.addPublicKey(ExampleMessages.ONLY_MASTER_KEY_PUBKEY_NO_KEY_FLAGS.getBytes());

        // encrypt
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(result);

        final OutputStream outputStream = BouncyGPG
                .encryptToStream()
                .withConfig(sendersKeyring)
                .setReferenceDateForKeyValidityTo(ExampleMessages.ONLY_MASTER_KEY_EXPIRY_DATE.minusSeconds(1))
                .withAlgorithms(DefaultPGPAlgorithmSuites.strongSuite())
                .toRecipient(ExampleMessages.ONLY_MASTER_KEY_UID_NO_KEY_FLAGS)
                .andDoNotSign()
                .binaryOutput()
                .andWriteTo(bufferedOutputStream);

        final InputStream is = new ByteArrayInputStream(
                ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes());
        Streams.pipeAll(is, outputStream);
        outputStream.close();
        bufferedOutputStream.close();
        is.close();

        /* test that the data can be encrypted.
           If the test fails, Bouncy-PGP would complain that it can't find a public key to encrypt with
         */

        final byte[] ciphertext = result.toByteArray();
        result.close();
        assertNotNull(ciphertext);
    }
}

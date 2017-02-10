package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting.EncryptWithOpenPGPTestDriverTest;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting.EncryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.openpgp.PGPException;

import java.io.File;
import java.io.IOException;

/**
 * Example configurations used in unit/-integration tests.
 */
public class Configs {

    public final static int KB = 1024;
    public final static int MB = 1024 * KB;
    public final static int GB = 1024 * MB;

    // Used in *FromFiles --> Useful for testing in the IDE
    private final static String TEST_RESOURCE_DIRECTORY = "./src/test/resources";

    public static EncryptionConfig buildConfigForEncryptionFromFiles(KeyringConfigCallback callback) {
        final KeyringConfig keyringConfig = keyringConfigFromFilesForRecipient(callback);


        EncryptionConfig encryptAndSignConfig = new EncryptionConfig(
                "recipient@example.com",
                "recipient@example.com",
                HashAlgorithm.sha1,
                keyringConfig);

        return encryptAndSignConfig;
    }

    public static EncryptionConfig buildConfigForEncryptionFromResources(String signatureSecretKeyId, String signatureSecretKeyPassword) {


        final KeyringConfig keyringConfig = keyringConfigFromResourceForSender(KeyringConfigCallbacks.withPassword(signatureSecretKeyPassword));


        EncryptionConfig encryptAndSignConfig = new EncryptionConfig(
                "sender@example.com",
                "recipient@example.com",
                HashAlgorithm.sha1,
                keyringConfig);

        return encryptAndSignConfig;

    }

    // ----- RECIPIENT

    public static KeyringConfig keyringConfigFromFilesForRecipient() {
        return keyringConfigFromFilesForRecipient(KeyringConfigCallbacks.withPasswordsFromMap(ExampleMessages.ALL_KEYRINGS_PASSWORDS));
    }

    public static KeyringConfig keyringConfigFromFilesForRecipient(KeyringConfigCallback callback) {
        return KeyringConfigs.withKeyRingsFromFiles(
                new File(TEST_RESOURCE_DIRECTORY + "/recipient.gpg.d/pubring.gpg"),
                new File(TEST_RESOURCE_DIRECTORY + "/recipient.gpg.d/secring.gpg"),
                callback);
    }


    public static KeyringConfig keyringConfigFromResourceForRecipient(KeyringConfigCallback callback) {
        return KeyringConfigs.withKeyRingsFromResources(EncryptWithOpenPGPTestDriverTest.class.getClassLoader(),
                "recipient.gpg.d/pubring.gpg",
                "recipient.gpg.d/secring.gpg",
                callback);
    }


    public static KeyringConfig keyringConfigFromResourceForRecipient() {
        return keyringConfigFromResourceForRecipient(KeyringConfigCallbacks.withPasswordsFromMap(ExampleMessages.ALL_KEYRINGS_PASSWORDS));
    }

    public static KeyringConfig keyringConfigInMemoryForSender() throws IOException, PGPException {
        final InMemoryKeyring keyring = KeyringConfigs.forGpgExportedKeys(KeyringConfigCallbacks.withPasswordsFromMap(ExampleMessages.ALL_KEYRINGS_PASSWORDS));

        keyring.addPublicKey(ExampleMessages.PUBKEY_SENDER.getBytes("US-ASCII"));
        keyring.addPublicKey(ExampleMessages.PUBKEY_SENDER_2.getBytes("US-ASCII"));
        keyring.addPublicKey(ExampleMessages.PUBKEY_SENDER_DSA_SIGN_ONLY.getBytes("US-ASCII"));
        keyring.addPublicKey(ExampleMessages.PUBKEY_RECIPIENT.getBytes("US-ASCII"));

        keyring.addSecretKey(ExampleMessages.SECRET_KEY_SENDER.getBytes("US-ASCII"));
        keyring.addSecretKey(ExampleMessages.SECRET_KEY_SENDER_DSA_SIGN_ONLY.getBytes("US-ASCII"));

        return keyring;
    }


    public static KeyringConfig keyringConfigInMemoryForRecipient() throws IOException, PGPException {
        final InMemoryKeyring keyring = KeyringConfigs.forGpgExportedKeys(KeyringConfigCallbacks.withPasswordsFromMap(ExampleMessages.ALL_KEYRINGS_PASSWORDS));

        keyring.addPublicKey(ExampleMessages.PUBKEY_SENDER.getBytes("US-ASCII"));
        keyring.addPublicKey(ExampleMessages.PUBKEY_SENDER_2.getBytes("US-ASCII"));
        keyring.addPublicKey(ExampleMessages.PUBKEY_SENDER_DSA_SIGN_ONLY.getBytes("US-ASCII"));
        keyring.addPublicKey(ExampleMessages.PUBKEY_RECIPIENT.getBytes("US-ASCII"));

        keyring.addSecretKey(ExampleMessages.SECRET_KEY_RECIPIENT.getBytes("US-ASCII"));

        return keyring;
    }
    // --------- Sender


    public static KeyringConfig keyringConfigFromFilesForSender() {
        return keyringConfigFromFilesForSender(KeyringConfigCallbacks.withPasswordsFromMap(ExampleMessages.ALL_KEYRINGS_PASSWORDS));
    }

    private static KeyringConfig keyringConfigFromFilesForSender(KeyringConfigCallback callback) {
        return KeyringConfigs.withKeyRingsFromFiles(
                new File(TEST_RESOURCE_DIRECTORY + "/sender.gpg.d/pubring.gpg"),
                new File(TEST_RESOURCE_DIRECTORY + "/sender.gpg.d/secring.gpg"),
                callback);
    }


    public static KeyringConfig keyringConfigFromResourceForSender(KeyringConfigCallback callback) {
        return KeyringConfigs.withKeyRingsFromResources(EncryptWithOpenPGPTestDriverTest.class.getClassLoader(),
                "sender.gpg.d/pubring.gpg",
                "sender.gpg.d/secring.gpg",
                callback);
    }

    public static KeyringConfig keyringConfigFromResourceForSender() {
        return keyringConfigFromResourceForSender(KeyringConfigCallbacks.withPasswordsFromMap(ExampleMessages.ALL_KEYRINGS_PASSWORDS));
    }


    public static EncryptionConfig buildConfigForEncryptionFromResources() {
        return buildConfigForEncryptionFromResources(
                "sender@example.com",
                "sender");
    }
}

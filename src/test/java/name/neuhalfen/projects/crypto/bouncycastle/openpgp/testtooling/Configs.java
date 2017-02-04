package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting.DecryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting.DefaultDecryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting.EncryptWithOpenPGPTest;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting.EncryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.KeyringConfigCallback;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.KeyringConfigCallbacks;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.tls.HashAlgorithm;

import java.io.File;

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
        final KeyringConfig keyringConfig = keyringConfigFromFiles(callback);


        EncryptionConfig encryptAndSignConfig = new EncryptionConfig(
                "recipient@example.com",
                "recipient@example.com",
                HashAlgorithm.sha1,
                SymmetricKeyAlgorithmTags.AES_128, keyringConfig);

        return encryptAndSignConfig;
    }

    public static EncryptionConfig buildConfigForEncryptionFromResources(String signatureSecretKeyId, String signatureSecretKeyPassword) {


        final KeyringConfig keyringConfig = keyringConfigFromResource(KeyringConfigCallbacks.withPassword(signatureSecretKeyPassword));


        EncryptionConfig encryptAndSignConfig = new EncryptionConfig(
                "recipient@example.com",
                "recipient@example.com",
                HashAlgorithm.sha1,
                SymmetricKeyAlgorithmTags.AES_128,
                keyringConfig);

        return encryptAndSignConfig;

    }

    private static KeyringConfig keyringConfigFromFiles(KeyringConfigCallback callback) {
        return KeyringConfig.withKeyRingsFromFiles(
                new File(TEST_RESOURCE_DIRECTORY + "/recipient.gpg.d/pubring.gpg"),
                new File(TEST_RESOURCE_DIRECTORY + "/recipient.gpg.d/secring.gpg"),
                callback);
    }

    public static EncryptionConfig buildConfigForEncryptionFromResources() {
        return buildConfigForEncryptionFromResources(
                "recipient@example.com",
                "recipient");
    }


    private static KeyringConfig keyringConfigFromResource(KeyringConfigCallback callback) {
        return KeyringConfig.withKeyRingsFromResources(EncryptWithOpenPGPTest.class.getClassLoader(),
                "recipient.gpg.d/pubring.gpg",
                "recipient.gpg.d/secring.gpg",
                callback);
    }


    public static DecryptionConfig buildConfigForDecryptionFromFiles(KeyringConfigCallback callback) {
        final DecryptionConfig decryptAndVerifyConfig = new DefaultDecryptionConfig(keyringConfigFromFiles(callback));

        return decryptAndVerifyConfig;
    }

    public static DecryptionConfig buildConfigForDecryptionFromResources(KeyringConfigCallback callback) {
        final DecryptionConfig decryptAndVerifyConfig = new DefaultDecryptionConfig(keyringConfigFromResource(callback));

        return decryptAndVerifyConfig;

    }

    public static DecryptionConfig buildConfigForDecryptionFromResources() {
        return buildConfigForDecryptionFromResources(KeyringConfigCallbacks.withPassword("recipient"));
    }

    public static DecryptionConfig buildConfigForDecryptionFromFiles() {
        return buildConfigForDecryptionFromFiles(KeyringConfigCallbacks.withPassword("recipient"));
    }
}

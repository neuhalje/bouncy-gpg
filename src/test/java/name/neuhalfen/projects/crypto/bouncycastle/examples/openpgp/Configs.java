package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp;


import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.DecryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptionConfig;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.tls.HashAlgorithm;

import java.io.File;

public class Configs {

    final static int KB = 1024;
    final static int MB = 1024 * KB;
    final static int GB = 1024 * MB;

    // Used in *FromFiles --> Useful for testing in the IDE
    private static String TEST_RESOURCE_DIRECTORY = "./src/test/resources";

    public static EncryptionConfig buildConfigForEncryptionFromFiles() {
        final EncryptionConfig encryptAndSignConfig = EncryptionConfig.withKeyRingsFromFiles(
                new File(TEST_RESOURCE_DIRECTORY + "/sender.gpg.d/pubring.gpg"),
                new File(TEST_RESOURCE_DIRECTORY + "/sender.gpg.d/secring.gpg"),
                "sender@example.com",
                "sender",
                "recipient@example.com",
                HashAlgorithm.sha1,
                SymmetricKeyAlgorithmTags.AES_128
        );


        return encryptAndSignConfig;
    }

    public static EncryptionConfig buildConfigForEncryptionFromResources() {
        final EncryptionConfig encryptAndSignConfig = EncryptionConfig.withKeyRingsFromResources(EncryptWithOpenPGPTest.class.getClassLoader(),
                "sender.gpg.d/pubring.gpg",
                "sender.gpg.d/secring.gpg",
                "sender@example.com",
                "sender",
                "recipient@example.com",
                HashAlgorithm.sha1,
                SymmetricKeyAlgorithmTags.AES_128
        );


        return encryptAndSignConfig;
    }

    public static DecryptionConfig buildConfigForDecryptionFromFiles() {
        final DecryptionConfig decryptAndVerifyConfig = DecryptionConfig.withKeyRingsFromFiles(
                new File(TEST_RESOURCE_DIRECTORY + "/recipient.gpg.d/pubring.gpg"),
                new File(TEST_RESOURCE_DIRECTORY + "/recipient.gpg.d/secring.gpg"),
                true, "recipient");

        return decryptAndVerifyConfig;
    }

    public static DecryptionConfig buildConfigForDecryptionFromResources() {
        final DecryptionConfig decryptAndVerifyConfig = DecryptionConfig.withKeyRingsFromResources(
                DecryptWithOpenPGPTest.class.getClassLoader(),
                "recipient.gpg.d/pubring.gpg",
                "recipient.gpg.d/secring.gpg",
                true, "recipient");

        return decryptAndVerifyConfig;
    }
}

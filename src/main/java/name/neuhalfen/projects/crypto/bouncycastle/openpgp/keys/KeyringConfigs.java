package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys;

import java.io.File;

/**
 * Factory for keyring configs.
 */
public class KeyringConfigs {

    /**
     * Create a decryption config by reading keyrings from files.
     *
     * @param publicKeyring E.g. src/test/resources/sender.gpg.d/pubring.gpg
     * @param secretKeyring E.g. src/test/resources/sender.gpg.d/secring.gpg
     * @return the config
     */
    public static DefaultKeyringConfig withKeyRingsFromFiles(final File publicKeyring,
                                                             final File secretKeyring,
                                                             KeyringConfigCallback callback) {

        return new FileBasedKeyringConfig(callback, publicKeyring, secretKeyring);
    }

    /**
     * Create a decryption config by reading keyrings from the classpath.
     *
     * @param classLoader       E.g. DecryptWithOpenPGPTest.class.getClassLoader()
     * @param publicKeyringPath E.g. "recipient.gpg.d/pubring.gpg"
     * @param secretKeyringPath E.g. "recipient.gpg.d/secring.gpg"
     * @return the config
     */
    public static DefaultKeyringConfig withKeyRingsFromResources(final ClassLoader classLoader,
                                                                 final String publicKeyringPath,
                                                                 final String secretKeyringPath,
                                                                 KeyringConfigCallback callback) {

        return new ResourceBasedKeyringConfig(callback, classLoader, publicKeyringPath, secretKeyringPath);
    }

}

package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;
import org.bouncycastle.openpgp.PGPException;

import java.io.File;
import java.io.IOException;

/**
 * Factory for keyring configs.
 */
public final class KeyringConfigs {

    // no instances
    private KeyringConfigs() {
    }

    /**
     * Create a config by reading keyrings from files.
     *
     * @param publicKeyring E.g. src/test/resources/sender.gpg.d/pubring.gpg
     * @param secretKeyring E.g. src/test/resources/sender.gpg.d/secring.gpg
     * @param callback      see KeyringConfigCallbacks
     * @return the config
     */
    public static KeyringConfig withKeyRingsFromFiles(final File publicKeyring,
                                                      final File secretKeyring,
                                                      KeyringConfigCallback callback) {
        if (publicKeyring == null) {
            throw new IllegalArgumentException(("keyring must not be null"));
        }
        if (secretKeyring == null) {
            throw new IllegalArgumentException(("secretKeyring must not be null"));
        }
        if (callback == null) {
            throw new IllegalArgumentException(("callback must not be null"));
        }

        return new FileBasedKeyringConfig(callback, publicKeyring, secretKeyring);
    }

    /**
     * Create a config by reading keyrings from the classpath.
     *
     * @param classLoader       E.g. DecryptWithOpenPGPTest.class.getClassLoader()
     * @param publicKeyringPath E.g. "recipient.gpg.d/pubring.gpg"
     * @param secretKeyringPath E.g. "recipient.gpg.d/secring.gpg"
     * @param callback          see KeyringConfigCallbacks
     * @return the config
     */
    public static KeyringConfig withKeyRingsFromResources(final ClassLoader classLoader,
                                                          final String publicKeyringPath,
                                                          final String secretKeyringPath,
                                                          final KeyringConfigCallback callback) {
        if (publicKeyringPath == null) {
            throw new IllegalArgumentException(("publicKeyringPath must not be null"));
        }
        if (secretKeyringPath == null) {
            throw new IllegalArgumentException(("secretKeyringPath must not be null"));
        }
        if (callback == null) {
            throw new IllegalArgumentException(("callback must not be null"));
        }

        return new ResourceBasedKeyringConfig(callback, classLoader, publicKeyringPath, secretKeyringPath);
    }

    /**
     * Create a config that can parse keys exported in gpg.
     *
     * @param callback see KeyringConfigCallbacks
     * @return the config
     * @throws IOException  IO is dangerous
     * @throws PGPException Could not create keyrings
     */
    public static InMemoryKeyring forGpgExportedKeys(final KeyringConfigCallback callback)
            throws IOException, PGPException {
        if (callback == null) {
            throw new IllegalArgumentException("callback must not be null");
        }
        return new InMemoryKeyring(callback);
    }
}

package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.KeyringConfigCallback;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

/**
 * Implements a keyring based on resources.
 * <p>
 * Use-case: Baked in GPG keyring (probably only with public keys)
 * without distributing separate keyring files.
 * <p>
 * See the unit tests for an example:
 * (in tests)  name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs
 */
public class ResourceBasedKeyringConfig extends DefaultKeyringConfig {


    private final ClassLoader classLoader;
    private final String publicKeyringPath;
    private final String secretKeyringPath;

    /**
     * @param callback          Callback to resolve secret key passwords
     * @param classLoader       The classloader used to open the resources
     * @param publicKeyringPath path passed to classLoader.getResourceAsStream
     * @param secretKeyringPath path passed to classLoader.getResourceAsStream
     */
    public ResourceBasedKeyringConfig(KeyringConfigCallback callback, ClassLoader classLoader, String publicKeyringPath, String secretKeyringPath) {
        super(callback);
        this.classLoader = classLoader;
        this.publicKeyringPath = publicKeyringPath;
        this.secretKeyringPath = secretKeyringPath;
    }

    @Override
    protected InputStream getPublicKeyRingStream() throws IOException {
        return classLoader.getResourceAsStream(publicKeyringPath);
    }

    @Override
    protected InputStream getSecretKeyRingStream() throws FileNotFoundException {
        return classLoader.getResourceAsStream(secretKeyringPath);
    }
}

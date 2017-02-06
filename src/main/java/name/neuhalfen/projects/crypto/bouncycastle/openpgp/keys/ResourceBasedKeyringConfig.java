package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

/**
 * Created by jens on 06/02/2017.
 */
class ResourceBasedKeyringConfig extends DefaultKeyringConfig {


    private final ClassLoader classLoader;
    private final String publicKeyringPath;
    private final String secretKeyringPath;

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

package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.KeyringConfigCallback;

import java.io.*;

/**
 * Load keyrings from files. These files are created and managed via gpg.
 */
public class FileBasedKeyringConfig extends DefaultKeyringConfig {
    private final File publicKeyring;
    private final File secretKeyring;

    public FileBasedKeyringConfig(KeyringConfigCallback callback, File publicKeyring, File secretKeyring) {
        super(callback);
        this.publicKeyring = publicKeyring;
        this.secretKeyring = secretKeyring;
    }

    @Override
    protected InputStream getPublicKeyRingStream() throws IOException {
        return new FileInputStream(publicKeyring);
    }

    @Override
    protected InputStream getSecretKeyRingStream() throws FileNotFoundException {
        return new FileInputStream(secretKeyring);
    }
}

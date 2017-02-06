package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys;

import java.io.*;

/**
 * Created by jens on 06/02/2017.
 */
class FileBasedKeyringConfig extends DefaultKeyringConfig {
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

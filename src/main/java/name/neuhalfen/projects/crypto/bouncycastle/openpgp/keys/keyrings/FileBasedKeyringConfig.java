package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;

import javax.annotation.Nonnull;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Load keyrings from files. These files are created and managed via gpg.
 */
final class FileBasedKeyringConfig extends DefaultKeyringConfig {

    @Nonnull
    private final File publicKeyring;
    @Nonnull
    private final File secretKeyring;

    public FileBasedKeyringConfig(@Nonnull KeyringConfigCallback callback, @Nonnull File publicKeyring, @Nonnull File secretKeyring) {
        super(callback);
        this.publicKeyring = publicKeyring;
        this.secretKeyring = secretKeyring;
    }

    @Nonnull
    @Override
    protected InputStream getPublicKeyRingStream() throws IOException {
        return Files.newInputStream(publicKeyring.toPath());
    }

    @Nonnull
    @Override
    protected InputStream getSecretKeyRingStream() throws IOException {
        return Files.newInputStream(secretKeyring.toPath());
    }
}

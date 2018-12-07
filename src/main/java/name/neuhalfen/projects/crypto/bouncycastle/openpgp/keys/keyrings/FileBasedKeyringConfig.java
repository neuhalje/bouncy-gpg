package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import javax.annotation.Nonnull;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.internal.Preconditions;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;

/**
 * Load keyrings from files. These files are created and managed via gpg.
 */
final class FileBasedKeyringConfig extends AbstractDefaultKeyringConfig {

  @Nonnull
  private final File publicKeyring;
  @Nonnull
  private final File secretKeyring;

  public FileBasedKeyringConfig(@Nonnull KeyringConfigCallback callback,
      @Nonnull File publicKeyring, @Nonnull File secretKeyring) {
    super(callback);
    Preconditions.checkNotNull(publicKeyring, "publicKeyring must not be null");
    Preconditions.checkNotNull(secretKeyring, "secretKeyring must not be null");

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

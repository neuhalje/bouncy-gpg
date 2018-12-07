package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;


import java.util.Map;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.internal.Preconditions;

/**
 * Factory for convenience implementations of KeyringConfigCallback. . {@link
 * KeyringConfigCallback}
 */
public final class KeyringConfigCallbacks {

  // no construction
  private KeyringConfigCallbacks() {
  }

  @SuppressWarnings("PMD.UseVarargs")
  public static KeyringConfigCallback withPassword(char[] passphrase) {
    return new StaticPasswordKeyringConfigCallback(passphrase);
  }

  public static KeyringConfigCallback withPassword(String passphrase) {
    Preconditions.checkNotNull(passphrase,"passphrase must not be null");

    return withPassword(passphrase.toCharArray());
  }

  public static KeyringConfigCallback withUnprotectedKeys() {
    return new UnprotectedKeysKeyringConfigCallback();
  }

  public static KeyringConfigCallback withPasswordsFromMap(
      Map<Long, char[]> mapSourceKeyIdToPassphrase) {
    Preconditions.checkNotNull(mapSourceKeyIdToPassphrase, "mapSourceKeyIdToPassphrase must not be null");

    return new StaticPasswordFromMapKeyringConfigCallback(mapSourceKeyIdToPassphrase);
  }
}

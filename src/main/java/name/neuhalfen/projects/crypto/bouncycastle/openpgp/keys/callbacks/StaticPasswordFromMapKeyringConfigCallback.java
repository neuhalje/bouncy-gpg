package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;


import java.util.HashMap;
import java.util.Map;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.internal.Preconditions;

final class StaticPasswordFromMapKeyringConfigCallback implements KeyringConfigCallback {

  private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
      .getLogger(StaticPasswordFromMapKeyringConfigCallback.class);

  private final Map<Long, char[]> keyIdToPassphrase;

  public StaticPasswordFromMapKeyringConfigCallback(Map<Long, char[]> mapSourceKeyIdToPassphrase) {
    Preconditions
        .checkNotNull(mapSourceKeyIdToPassphrase, "mapSourceKeyIdToPassphrase must not be null");
    keyIdToPassphrase = new HashMap<>(mapSourceKeyIdToPassphrase);
  }

  @Override
  public char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyId) {
    final char[] password = keyIdToPassphrase.get(keyId);
    if (password == null) {
      LOGGER.debug("No passphrase found for keyID 0x{}.", Long.toHexString(keyId));
    }
    return password;
  }
}

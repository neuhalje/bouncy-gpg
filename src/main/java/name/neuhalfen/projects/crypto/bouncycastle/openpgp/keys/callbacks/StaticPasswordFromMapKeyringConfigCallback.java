package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;


import java.util.HashMap;
import java.util.Map;

final class StaticPasswordFromMapKeyringConfigCallback implements KeyringConfigCallback {

    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(StaticPasswordFromMapKeyringConfigCallback.class);

    private final Map<Long, char[]> keyIdToPassphrase;

    public StaticPasswordFromMapKeyringConfigCallback(Map<Long, char[]> copySourceKeyIdToPassphrase) {
        keyIdToPassphrase = new HashMap<>(copySourceKeyIdToPassphrase);
    }

    @Override
    public char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyID) {
        final char[] password = keyIdToPassphrase.get(keyID);
        if (password == null) {
            LOGGER.debug("No passphrase found for keyID 0x{}.", Long.toHexString(keyID));
        }
        return password;
    }
}

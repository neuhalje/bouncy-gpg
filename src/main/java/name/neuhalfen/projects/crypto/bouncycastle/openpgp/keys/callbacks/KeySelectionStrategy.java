package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

import java.io.IOException;
import java.util.Set;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;

public interface KeySelectionStrategy {

  /**
   * <p>
   * Extract a signing/encryption key from the keyrings.
   * </p>
   * <p>
   * The implementation should try to find the best matching key.
   * </p>
   *
   * @param purpose Return a singing or encryption key?
   * @param uid The recipient ("FOR_ENCRYPTION") or the sender ("FOR_SIGNING")
   * @param keyring search here
   *
   * @return a public key that can be used for signing, null if non is found
   *
   * @throws IOException something with IO went wrong
   * @throws PGPException something with PGP went wrong
   */
  @Nullable
  PGPPublicKey selectPublicKey(final PURPOSE purpose, final String uid,
      final KeyringConfig keyring) throws PGPException, IOException;

  /**
   * List all keys accepted for signatures.
   *
   * The implementation should try to find the best matching key.
   *
   * @param uid The sender
   * @param keyring search here
   *
   * @return public keys that can be accepted for signatues, empty set if none are found
   *
   * @throws IOException something with IO went wrong
   * @throws PGPException something with PGP went wrong
   */
  Set<PGPPublicKey> validPublicKeysForVerifyingSignatures(final String uid,
      final KeyringConfig keyring) throws PGPException, IOException;

  enum PURPOSE {
    /**
     * FOR_ENCRYPTION: Select a public key suitable for encryption.  MUST check if private key is
     * available.
     */
    FOR_ENCRYPTION,

    /**
     * FOR_SIGNING: Select a public key suitable for signing.  MUST check if private key is
     * available.
     */
    FOR_SIGNING,
  }
}

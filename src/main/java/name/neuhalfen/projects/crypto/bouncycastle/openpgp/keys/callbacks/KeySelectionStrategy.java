package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

import javax.annotation.Nullable;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

public interface KeySelectionStrategy {

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
    /**
     * FOR_SIGNATURE_VALIDATION: Select a public key suitable for signature validation.
     * Private key is not relevant.
     */
    FOR_SIGNATURE_VALIDATION
  }


  /**
   * Extract a signing/encryption key from the keyrings.
   *
   * The implementation should try to find the best matching key.
   *
   * @param purpose Return a singing or encryption key?
   * @param keyring search here
   *
   * @return a public key that can be used for signing, null if non is found
   */
  @Nullable
  PGPPublicKey selectPublicKey(final PURPOSE purpose, final PGPPublicKeyRing keyring);

}

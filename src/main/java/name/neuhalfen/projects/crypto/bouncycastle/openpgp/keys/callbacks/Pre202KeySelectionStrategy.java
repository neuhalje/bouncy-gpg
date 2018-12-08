package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

/**
 * This implements the key selection strategy for BouncyGPG pre 2.0.2
 *
 * This strategy is flawed for signature keys and can return signature keys
 * in violation of the key flags (see rfc4880 section-5.2.3.21).
 *
 * !! Only use this if the old behaviour pre-2.0.2 is needed !!
 *
 * https://tools.ietf.org/html/rfc4880#section-5.2.3.21
 */
@Deprecated()
public final class Pre202KeySelectionStrategy implements KeySelectionStrategy {

  private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
      .getLogger(Pre202KeySelectionStrategy.class);

  /**
   * Extract a signing key from the keyring. The implementation tries to find the best matching key.
   * . FIXME: refactor this, so that we use all keys from the keyring as valid signing keys .
   * Detection of possible signing keys is heuristic at best.
   *
   * @param keyring search here
   *
   * @return a public key that can be used for signing, null if non founf
   */
  @Nullable
  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.DataflowAnomalyAnalysis"})
  private static PGPPublicKey extractSigningPublicKey(PGPPublicKeyRing keyring) {

    int highestScore = Integer.MIN_VALUE;

    PGPPublicKey ret = null;

    for (final PGPPublicKey pubKey : keyring) {
      final int score = calculateSigningKeyScore(pubKey);
      if (score > highestScore) {
        ret = pubKey;
        highestScore = score;
      }
    }
    return ret;
  }

  /*
   * Try to find the best signing key.
   * - Try not to use master keys (if possible) because signing should be done with subkeys
   * - Give a bonus to "sign only" keys (or 'AUTH' only keys - these are not detected)
   */
  @SuppressWarnings("PMD.LawOfDemeter")
  private static int calculateSigningKeyScore(PGPPublicKey pubKey) {
    int score = 0;
    if (!pubKey.isMasterKey()) {
      score += 100;
    }
    if (!pubKey.isEncryptionKey()) {
      score += 10;
    }
    return score;
  }

  /**
   * ONLY USED TO TEST AGAINST OLD BEHAVIOUR!!!
   *
   * Extracts the first secret signing key for UID {@code signatureUid} suitable for signature
   * generation from a key ring collection {@code secretKeyRings}.
   *
   * @param pgpSec a Collection of secret key rings
   * @param signingKeyUid signature Key uid to search for
   *
   * @return the first secret key for signatureUid suitable for signatures
   *
   * @throws PGPException if no key ring or key with that Uid is found
   */
  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.DefaultPackage"})
  static PGPSecretKey extractSecretSigningKeyFromKeyrings(
      final PGPSecretKeyRingCollection pgpSec, final String signingKeyUid)
      throws PGPException {
    int highestScore = Integer.MIN_VALUE;

    PGPSecretKey key = null;

    final Iterator<PGPSecretKeyRing> ringIterator = pgpSec
        .getKeyRings("<" + signingKeyUid + ">", true);
    while (ringIterator.hasNext()) {
      final PGPSecretKeyRing kRing = ringIterator.next();
      final Iterator<PGPSecretKey> secretKeyIterator = kRing.getSecretKeys();

      while (secretKeyIterator.hasNext()) {
        final PGPSecretKey secretKey = secretKeyIterator.next();
        final int score = calculateSigningKeyScore(secretKey.getPublicKey());

        if (secretKey.isSigningKey() && score > highestScore) {
          key = secretKey;
          highestScore = score;
        }
      }
    }

    if (key == null) {
      throw new PGPException(
          String.format("Can't find signing key for uid '%s' in key ring.", signingKeyUid));
    }
    LOGGER.trace("Extracted secret signing key for UID '{}'.", signingKeyUid);

    return key;
  }

  /**
   * Returns the 'best' encryption key encountered in {@code publicKeyRing}.
   *
   * @param publicKeyRing the public key ring
   *
   * @return the encryption key
   */
  @Nullable
  @SuppressWarnings({"PMD.LawOfDemeter"})
  private static PGPPublicKey getEncryptionKey(final PGPPublicKeyRing publicKeyRing) {
    int score;
    int highestScore = Integer.MIN_VALUE;

    PGPPublicKey returnKey = null;

    for (final PGPPublicKey pubKey : publicKeyRing) {
      score = calculateEncryptionKeyScore(pubKey);
      if (score > highestScore) {
        returnKey = pubKey;
        highestScore = score;
      }
    }
    return returnKey;
  }

  /*
   * Try to find the best encryption key.
   * - Try not to use master keys (if possible) because encryption should be done with subkeys
   */
  @SuppressWarnings("PMD.OnlyOneReturn")
  private static int calculateEncryptionKeyScore(PGPPublicKey pubKey) {
    if (!pubKey.isEncryptionKey()) {
      return Integer.MIN_VALUE;
    }

    int score = 0;
    if (!pubKey.isMasterKey()) {
      score++;
    }

    return score;
  }

  @Nullable
  @Override
  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.OnlyOneReturn"})
  public PGPPublicKey selectPublicKey(PURPOSE purpose, String uid, KeyringConfig keyringConfig)
      throws PGPException, IOException {

    final Iterator<PGPPublicKeyRing> keyRings = keyringConfig.getPublicKeyRings()
        .getKeyRings(uid, true, true);

    if (!keyRings.hasNext()) {
      return null;
    }

    final PGPPublicKeyRing publicKeyRing = keyRings
        .next();

    switch (purpose) {
      case FOR_SIGNING:
        // This DOES NOT CHECK FOR PRIVATE KEY EXISTENCE!
        return extractSigningPublicKey(publicKeyRing);
      case FOR_ENCRYPTION:
        return getEncryptionKey(publicKeyRing);
      default:
        return null;
    }
  }

  @Override
  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.OnlyOneReturn"})
  public Set<PGPPublicKey> validPublicKeysForVerifyingSignatures(String uid,
      KeyringConfig keyringConfig) throws PGPException, IOException {

    final Iterator<PGPPublicKeyRing> keyRings = keyringConfig.getPublicKeyRings()
        .getKeyRings(uid, true, true);

    if (!keyRings.hasNext()) {
      return Collections.EMPTY_SET;
    }

    final PGPPublicKey pgpPublicKey = extractSigningPublicKey(keyRings.next());
    final HashSet<PGPPublicKey> hashSet = new HashSet<>();
    hashSet.add(pgpPublicKey);
    return hashSet;
  }
}




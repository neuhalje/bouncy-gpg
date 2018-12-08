package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.time.Instant;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyFlags;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;

/**
 * This implements the key selection strategy for BouncyGPG .
 * This strategy is tries to implement rfc4880 section-5.2.3.21.
 * https://tools.ietf.org/html/rfc4880#section-5.2.3.21
 */
public class Rfc4880KeySelectionStrategy implements KeySelectionStrategy {

  private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
      .getLogger(Rfc4880KeySelectionStrategy.class);

  private final Instant dateOfTimestampVerification;
  private final boolean ignoreCase;
  private final boolean matchPartial;

  /**
   * Construct an instance with matchPartial and ignoreCase set to true.
   *
   * @param dateOfTimestampVerification The date used for key expiration date checks as "now".
   */
  public Rfc4880KeySelectionStrategy(final Instant dateOfTimestampVerification) {
    this(dateOfTimestampVerification, true, true);
  }


  /**
   * Create an instance of this strategy.
   *
   * @param matchPartial if true userID need only be a substring of an actual ID string to
   *     match.
   * @param ignoreCase if true case is ignored in user ID comparisons.
   * @param dateOfTimestampVerification The date used for key expiration date checks as "now".
   */
  public Rfc4880KeySelectionStrategy(final Instant dateOfTimestampVerification,
      final boolean matchPartial, final boolean ignoreCase) {
    requireNonNull(dateOfTimestampVerification, "dateOfTimestampVerification must not be null");
    this.dateOfTimestampVerification = dateOfTimestampVerification;
    this.matchPartial = matchPartial;
    this.ignoreCase = ignoreCase;

  }

  /**
   * The date used for key expiration date checks as "now".
   *
   * @return dateOfTimestampVerification
   */
  protected Instant getDateOfTimestampVerification() {
    return dateOfTimestampVerification;
  }

  /**
   * Return all keyrings that ARE valid keys for the given uid.
   *
   * Deriving classes can override this.
   *
   * @param uid the userid as passed by upstream.
   * @param keyringConfig the keyring config
   * @param purpose what is the requested key to be used for
   *
   * @return Set with keyrings, never null.
   *
   * @throws PGPException Something with BouncyCastle went wrong
   * @throws IOException IO is dangerous
   */
  @SuppressWarnings({"PMD.LawOfDemeter"})
  protected Set<PGPPublicKeyRing> publicKeyRingsForUid(final PURPOSE purpose, final String uid,
      KeyringConfig keyringConfig)
      throws IOException, PGPException {

    final Set<PGPPublicKeyRing> keyringsForUid = new HashSet<>();

    final Iterator<PGPPublicKeyRing> keyRings = keyringConfig.getPublicKeyRings()
        .getKeyRings(uid, matchPartial, ignoreCase);

    while (keyRings.hasNext()) {
      keyringsForUid.add(keyRings.next());
    }

    return keyringsForUid;
  }


  @Override
  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.ShortVariable"})
  public Set<PGPPublicKey> validPublicKeysForVerifyingSignatures(String uid,
      KeyringConfig keyringConfig) throws PGPException, IOException {

    requireNonNull(uid, "uid must not be null");
    requireNonNull(keyringConfig, "keyringConfig must not be null");

    final Set<PGPPublicKeyRing> publicKeyrings = this
        .publicKeyRingsForUid(PURPOSE.FOR_SIGNING, uid, keyringConfig);

    return publicKeyrings.stream()
        .flatMap(keyring -> StreamSupport.stream(keyring.spliterator(), false))
        .filter(this::isVerificationKey)
        .filter(this::isNotRevoked)
        .filter(this::isNotExpired)
        .collect(Collectors.toSet());
  }

  @Nullable
  @Override
  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.ShortVariable", "PMD.OnlyOneReturn"})
  public PGPPublicKey selectPublicKey(PURPOSE purpose, String uid, KeyringConfig keyringConfig)
      throws PGPException, IOException {

    requireNonNull(purpose, "purpose must not be null");
    requireNonNull(uid, "uid must not be null");
    requireNonNull(keyringConfig, "keyringConfig must not be null");

    final Set<PGPPublicKeyRing> publicKeyrings = this
        .publicKeyRingsForUid(purpose, uid, keyringConfig);

    final PGPSecretKeyRingCollection secretKeyRings = keyringConfig.getSecretKeyRings();

    switch (purpose) {
      case FOR_SIGNING:
        return publicKeyrings.stream()
            .flatMap(keyring -> StreamSupport.stream(keyring.spliterator(), false))
            .filter(this::isVerificationKey)
            .filter(this::isNotRevoked)
            .filter(this::isNotExpired)
            .filter(hasPrivateKey(secretKeyRings))
            .reduce((a, b) -> b)
            .orElse(null);

      case FOR_ENCRYPTION:
        return publicKeyrings.stream()
            .flatMap(keyring -> StreamSupport.stream(keyring.spliterator(), false))
            .filter(this::isEncryptionKey)
            .filter(this::isNotRevoked)
            .filter(this::isNotExpired)
            .reduce((a, b) -> b)
            .orElse(null);

      default:
        return null;
    }
  }


  @SuppressWarnings({"PMD.LinguisticNaming"})
  protected Predicate<PGPPublicKey> hasPrivateKey(final PGPSecretKeyRingCollection secretKeyRings) {
    return pubKey -> {
      requireNonNull(pubKey, "pubKey must not be null");

      try {
        final boolean hasPrivateKey = secretKeyRings.contains(pubKey.getKeyID());

        if (!hasPrivateKey) {
          LOGGER.trace("Skipping pubkey {} (no private key found)",
              Long.toHexString(pubKey.getKeyID()));
        }

        return hasPrivateKey;
      } catch (PGPException e) {
        // ignore this for filtering
        LOGGER.debug("Failed to test for private key for pubkey " + pubKey//NOPMD:GuardLogStatement
            .getKeyID());
        return false;
      }
    };
  }


  protected boolean isNotMasterKey(PGPPublicKey pubKey) {
    return !pubKey.isMasterKey();
  }

  @SuppressWarnings({"PMD.LawOfDemeter"})
  protected boolean isNotExpired(PGPPublicKey pubKey) {
    return !isExpired(pubKey);
  }

  @SuppressWarnings({"PMD.LawOfDemeter"})
  protected boolean isExpired(PGPPublicKey pubKey) {
    requireNonNull(pubKey, "pubKey must not be null");

    // getValidSeconds == 0 means: no expiration date
    final boolean hasExpiryDate = pubKey.getValidSeconds() > 0;

    final boolean isExpired;

    if (hasExpiryDate) {
      final Instant expiryDate = pubKey.getCreationTime().toInstant()
          .plusSeconds(pubKey.getValidSeconds());
      isExpired = expiryDate
          .isBefore(getDateOfTimestampVerification());

      if (isExpired) {
        LOGGER.trace("Skipping pubkey {} (expired since {})",
            Long.toHexString(pubKey.getKeyID()), expiryDate.toString());
      }
    } else {
      isExpired = false;
    }

    return isExpired;
  }


  protected boolean isEncryptionKey(PGPPublicKey publicKey) {
    requireNonNull(publicKey, "publicKey must not be null");

    final long keyFlags = extractPublicKeyFlags(publicKey);

    final boolean canEncryptCommunication =
        (keyFlags & PGPKeyFlags.CAN_ENCRYPT_COMMS) == PGPKeyFlags.CAN_ENCRYPT_COMMS;

    final boolean canEncryptStorage =
        (keyFlags & PGPKeyFlags.CAN_ENCRYPT_STORAGE) == PGPKeyFlags.CAN_ENCRYPT_STORAGE;

    return canEncryptCommunication || canEncryptStorage;
  }

  protected boolean isVerificationKey(PGPPublicKey pubKey) {
    final boolean isVerficationKey =
        (extractPublicKeyFlags(pubKey) & PGPKeyFlags.CAN_SIGN) == PGPKeyFlags.CAN_SIGN;

    if (!isVerficationKey) {
      LOGGER.trace("Skipping pubkey {} (no signing key)",
          Long.toHexString(pubKey.getKeyID()));
    }
    return isVerficationKey;
  }


  protected boolean isRevoked(PGPPublicKey pubKey) {
    requireNonNull(pubKey, "pubKey must not be null");

    final boolean hasRevocation = pubKey.hasRevocation();
    if (hasRevocation) {
      LOGGER.trace("Skipping pubkey {} (revoked)",
          Long.toHexString(pubKey.getKeyID()));
    }
    return hasRevocation;
  }

  protected boolean isNotRevoked(PGPPublicKey publicKey) {
    return !isRevoked(publicKey);
  }

  @SuppressWarnings({"PMD.LawOfDemeter"})
  protected long extractPublicKeyFlags(PGPPublicKey publicKey) {
    requireNonNull(publicKey, "publicKey must not be null");

    long aggregatedKeyFlags = 0;

    final Iterator<PGPSignature> directKeySignatures = publicKey.getSignatures();

    while (directKeySignatures.hasNext()) {
      final PGPSignature signature = directKeySignatures.next();
      final PGPSignatureSubpacketVector hashedSubPackets = signature.getHashedSubPackets();

      final int keyFlags = hashedSubPackets.getKeyFlags();
      aggregatedKeyFlags |= keyFlags;
    }
    return aggregatedKeyFlags;
  }
}




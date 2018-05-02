package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

import java.io.IOException;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
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
 *
 * This strategy is tries to implement rfc4880 section-5.2.3.21.
 * *
 * https://tools.ietf.org/html/rfc4880#section-5.2.3.21
 */
public class Rfc4880KeySelectionStrategy implements KeySelectionStrategy {

  private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
      .getLogger(Rfc4880KeySelectionStrategy.class);

  private final Date dateOfTimestampVerification;

  /**
   * The date used for key expiration date checks as "now".
   *
   * @return dateOfTimestampVerification
   */
  protected Date getDateOfTimestampVerification() {
    return dateOfTimestampVerification;
  }


  /**
   * @param dateOfTimestampVerification The date used for key expiration date checks as "now".
   */
  public Rfc4880KeySelectionStrategy(final Date dateOfTimestampVerification) {
    this.dateOfTimestampVerification = dateOfTimestampVerification;
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
   * @throws PGPException  Something with BouncyCastle went wrong
   * @throws IOException  IO is dangerous
   */
  @SuppressWarnings({"PMD.LawOfDemeter"})
  protected Set<PGPPublicKeyRing> publicKeyRingsForUid(final PURPOSE purpose, final String uid,
      KeyringConfig keyringConfig)
      throws IOException, PGPException {

    Set<PGPPublicKeyRing> keyringsForUid = new HashSet<>();

    final String uidQuery;
    final boolean uidAlreadyInBrackets = uid.matches(".*<.*>.*");
    if (uidAlreadyInBrackets) {
      uidQuery = uid;
    } else {
      uidQuery = "<" + uid + ">";
    }

    final Iterator<PGPPublicKeyRing> keyRings = keyringConfig.getPublicKeyRings()
        .getKeyRings(uidQuery, true, true);

    while (keyRings.hasNext()) {
      keyringsForUid.add(keyRings.next());
    }

    return keyringsForUid;
  }


  @Override
  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.ShortVariable"})
  public Set<PGPPublicKey> validPublicKeysForVerifyingSignatures(String uid,
      KeyringConfig keyringConfig) throws PGPException, IOException {

    final Set<PGPPublicKeyRing> publicKeyrings = this
        .publicKeyRingsForUid(PURPOSE.FOR_SIGNING, uid, keyringConfig);

    Set<PGPPublicKey> validKeys = new HashSet<>();
    for (PGPPublicKeyRing p : publicKeyrings) {
      Iterator<PGPPublicKey> keys = p.iterator();
      while (keys.hasNext()) {
        PGPPublicKey key = keys.next();
        if (isVerificationKey(key) && isNotRevoked(key) && isNotExpired(key)) {
          validKeys.add(key);
        }
      }
    }
    return validKeys;
  }

  @Nullable
  @Override
  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.ShortVariable", "PMD.OnlyOneReturn"})
  public PGPPublicKey selectPublicKey(PURPOSE purpose, String uid, KeyringConfig keyringConfig)
      throws PGPException, IOException {

    final Set<PGPPublicKeyRing> publicKeyrings = this
        .publicKeyRingsForUid(purpose, uid, keyringConfig);

    final PGPSecretKeyRingCollection secretKeyRings = keyringConfig.getSecretKeyRings();

    PGPPublicKey publicKey = null;
    switch (purpose) {
      case FOR_SIGNING:
        for (PGPPublicKeyRing ring : publicKeyrings) {
          Iterator<PGPPublicKey> iterator = ring.iterator();
          while (iterator.hasNext()) {
            PGPPublicKey key = iterator.next();
            if (isVerificationKey(key)
                    && isNotRevoked(key)
                    && isNotExpired(key)
                    && hasPrivateKey(key, secretKeyRings)) {
              publicKey = key;
            }
          }
        }
        return publicKey;

      case FOR_ENCRYPTION:
        for (PGPPublicKeyRing ring : publicKeyrings) {
          Iterator<PGPPublicKey> iterator = ring.iterator();
          while (iterator.hasNext()) {
            PGPPublicKey key = iterator.next();
            if (isEncryptionKey(key)
                    && isNotRevoked(key)
                    && isNotExpired(key)) {
              publicKey = key;
            }
          }
        }
        return publicKey;

      default:
        return null;
    }
  }

  protected boolean hasPrivateKey(PGPPublicKey pubKey, PGPSecretKeyRingCollection secretKeyRings) {
    boolean result = false;
    try {
      final boolean hasPrivateKey = secretKeyRings.contains(pubKey.getKeyID());

      if (!hasPrivateKey) {
        LOGGER.trace("Skipping pubkey {} (no private key found)",
                Long.toHexString(pubKey.getKeyID()));
      }

      result = hasPrivateKey;
    } catch (PGPException e) {
      // ignore this for filtering
      LOGGER.debug("Failed to test for private key for pubkey " + pubKey.getKeyID());
    }

    return result;
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
    // getValidSeconds == 0 means: no expiration date
    boolean hasExpiryDate = pubKey.getValidSeconds() > 0;

    final boolean isExpired;

    if (hasExpiryDate) {
      final Date expiryDate = new Date(pubKey.getCreationTime().getTime()
              + 1000L * pubKey.getValidSeconds());
      isExpired = expiryDate
          .before(getDateOfTimestampVerification());

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


  public boolean isRevoked(PGPPublicKey pubKey) {
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




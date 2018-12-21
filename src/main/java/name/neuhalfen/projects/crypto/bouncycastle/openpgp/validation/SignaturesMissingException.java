package name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation;

import java.security.SignatureException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import javax.annotation.Nullable;

public class SignaturesMissingException extends SignatureException {

  private static final long serialVersionUID = -7306258581793628971L;
  private final Set<MissingSignature> missingSignatures;
  private final SetSemantics missingSignaturesSemantics;

  public SignaturesMissingException(final String message) {
    super(message);
    this.missingSignaturesSemantics = SetSemantics.ALL_SIGNATURES_MISSING;
    this.missingSignatures = Collections.EMPTY_SET;
  }

  public SignaturesMissingException(final String message,
      final Set<MissingSignature> missingSignatures,
      final SetSemantics missingSignaturesSemantics) {
    super(message);
    this.missingSignatures = Collections.unmodifiableSet(new HashSet<>(missingSignatures));
    this.missingSignaturesSemantics = missingSignaturesSemantics;
  }

  /**
   * The semantics of the set are up to the "thrower" and described in {@link
   * #getMissingSignaturesSemantics()}.
   *
   * @return key references that were missing
   */
  public Set<MissingSignature> getMissingSignatures() {
    return missingSignatures;
  }

  public SetSemantics getMissingSignaturesSemantics() {
    return missingSignaturesSemantics;
  }

  public enum SetSemantics {
    /**
     * Verification would have been successful if a valid signature for ANY of the passed keys
     * would have been present.
     */
    ANY_SIGNATURE_MISSING,
    /**
     * Verification would have been successful if valid signatures for ALL of the passed keys
     * would have been present.
     */
    ALL_SIGNATURES_MISSING
  }

  /**
   * The key reference for a missing signature. If uid or keyId (or both) are set
   * depends on the context.
   */
  public final static class MissingSignature {


    @Nullable
    private final String uid;
    @Nullable
    private final Long keyId;

    public MissingSignature(@Nullable final String uid, @Nullable final Long keyId) {
      this.uid = uid;
      this.keyId = keyId;
    }

    /**
     * Create a MissingSignature instance with only the keyId set
     *
     * @param keyId key Id
     *
     * @return MissingSignature instance
     */
    public static MissingSignature fromKeyId(final Long keyId) {
      Objects.requireNonNull(keyId, "keyId must not be null");
      return new MissingSignature(null, keyId);
    }

    /**
     * Map a set of key Ids to a set of MissingSignature instances with only the keyIds set.
     *
     * @param keyIds key Id set
     *
     * @return MissingSignature instances
     */
    public static Set<MissingSignature> fromKeyIds(final Set<Long> keyIds) {
      Objects.requireNonNull(keyIds, "keyIds must not be null");

      return keyIds.stream() // NOPMD: demeter
          .map(SignaturesMissingException.MissingSignature::fromKeyId).collect(
              Collectors.toSet());
    }

    /**
     * Create a MissingSignature instance with only the uid set
     *
     * @param uid user id
     *
     * @return MissingSignature instance
     */
    public static MissingSignature fromUid(final String uid) {
      Objects.requireNonNull(uid, "uid must not be null");
      return new MissingSignature(uid, null);
    }

    /**
     * Map a set of key Ids to a set of MissingSignature instances with only the user ids set.
     *
     * @param uids user Id set
     *
     * @return MissingSignature instances
     */
    public static Set<MissingSignature> fromUids(final Set<String> uids) {
      Objects.requireNonNull(uids, "uids must not be null");

      return uids.stream() // NOPMD: demeter
          .map(SignaturesMissingException.MissingSignature::fromUid).collect(
              Collectors.toSet());
    }

    @Nullable
    public String getUid() {
      return uid;
    }

    @Nullable
    public Long getKeyId() {
      return keyId;
    }

    @Override
    @SuppressWarnings({"PMD.OnlyOneReturn", "PMD.LawOfDemeter"})
    public boolean equals(final Object other) {
      if (this == other) {
        return true;
      }
      if (other == null || getClass() != other.getClass()) {
        return false;
      }
      final MissingSignature that = (MissingSignature) other;
      return Objects.equals(getUid(), that.getUid())
          && Objects.equals(getKeyId(), that.getKeyId());
    }

    @Override
    public int hashCode() {
      return Objects.hash(getUid(), getKeyId());
    }

    @Override
    public String toString() {
      return new StringBuilder("MissingSignature{")
          .append("uid='").append(uid == null ? "???" : uid).append('\'')
          .append(", keyId=0x").append(keyId == null ? "???" : Long.toHexString(keyId))
          .append('}').toString();
    }
  }
}

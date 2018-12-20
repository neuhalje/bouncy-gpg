package name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation;


import static java.util.Objects.requireNonNull;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationHelper.knownKeysWithGoodSignatures;

import java.io.IOException;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignaturesMissingException.SetSemantics;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPSignatureList;

final class RequireSpecificSignatureValidationForUserIdsStrategy implements
    SignatureValidationStrategy {

  private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
      .getLogger(RequireSpecificSignatureValidationForUserIdsStrategy.class);

  private final Map<String, Set<Long>> keysByUid;

  /**
   * @param keysByUid Each uid requires a signature that can be satisfied by any of its keys.
   */
  RequireSpecificSignatureValidationForUserIdsStrategy(Map<String, Set<Long>> keysByUid) {
    requireNonNull(keysByUid, "keysByUid must not be null");
    this.keysByUid = new HashMap<>(keysByUid);
  }

  /*
   * Find the (first) uid a given keyid belongs to
   */
  @Nullable
  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.OnlyOneReturn"})
  private String uidForKeyId(long keyId) {
    for (final String uid : keysByUid.keySet()) {
      final Set<Long> keyIds = keysByUid.get(uid);
      if (keyIds.contains(keyId)) {
        return uid;
      }
    }
    return null;
  }

  @Override
  @SuppressWarnings("PMD.CyclomaticComplexity")
  public void validateSignatures(PGPObjectFactory factory,
      Map<Long, PGPOnePassSignature> onePassSignatures) throws
      SignatureException, PGPException, IOException {

    requireNonNull(factory, "factory must not be null");
    requireNonNull(onePassSignatures, "onePassSignatures must not be null");

    final PGPSignatureList signatureList = extractPgpSignatures(factory);

    final Set<String> signaturesRequired = new HashSet<>(
        keysByUid.keySet());

    final Set<Long> knownKeysWithGoodSignatures = knownKeysWithGoodSignatures(onePassSignatures,
        signatureList);

    // cross uid of the list
    knownKeysWithGoodSignatures // NOPMD: demeter
        .forEach(keyId -> signaturesRequired.remove(uidForKeyId(keyId)));

    final boolean successfullyVerified = signaturesRequired.isEmpty();

    if (successfullyVerified) {
      LOGGER.debug("Signature verification success");
    } else {
      throw createMissingSignaturesException(signaturesRequired);
    }
  }


  private PGPSignatureList extractPgpSignatures(final PGPObjectFactory factory)
      throws IOException, SignaturesMissingException {
    final PGPSignatureList signatureList = (PGPSignatureList) factory.nextObject();

    if (signatureList == null || signatureList.isEmpty()) {
      // This statement is not reached in normal flow
      // because decryption errs first when it does not find
      // the one pass signature before the data object.
      throw createMissingSignaturesException(keysByUid.keySet());
    }
    return signatureList;
  }

  private SignaturesMissingException createMissingSignaturesException(Set<String> missingUids) {
    return new SignaturesMissingException(
        "Signature verification failed because all of the following signatures "
            + "(by userId) are missing.",
        SignaturesMissingException.MissingSignature.fromUids( //NOPMD: Demeter
            missingUids),
        SetSemantics.ALL_SIGNATURES_MISSING);
  }

  @Override
  public boolean isRequireSignatureCheck() {
    return true;
  }
}

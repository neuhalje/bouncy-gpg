package name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation;


import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nullable;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPSignature;
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

    // verify the signature
    final PGPSignatureList signatureList = (PGPSignatureList) factory.nextObject();

    if (signatureList == null || signatureList.isEmpty()) {
      // This statement is not reached in normal flow
      // because decryption errs first when it does not find
      // the one pass signature before the data object.
      throw new PGPException("No signatures found!");
    }

    final Set<String> signaturesRequiredForTheseKeysCheckList = new HashSet<>(
        keysByUid.keySet());

    for (final PGPSignature messageSignature : signatureList) {
      final PGPOnePassSignature ops = onePassSignatures.get(messageSignature.getKeyID());

      final boolean isHasPubKeyForSignature = ops != null;
      if (isHasPubKeyForSignature) {
        final boolean isThisSignatureGood = ops.verify(messageSignature); // NOPMD : Demeter
        final String uid = uidForKeyId(messageSignature.getKeyID());

        LOGGER.debug("{} validated signature with key 0x{} ({})",
            isThisSignatureGood ? "Successfully" : "Failed to",
            Long.toHexString(messageSignature.getKeyID()),
            uid == null ? "<unknown uid>" : uid);

        if (isThisSignatureGood && uid != null) {
          signaturesRequiredForTheseKeysCheckList.remove(uid);
        }
      }
    }

    final boolean successfullyVerified = signaturesRequiredForTheseKeysCheckList.isEmpty();

    if (successfullyVerified) {
      LOGGER.debug("Signature verification success");
    } else {
      throw new SignatureException(
          "Signature verification failed! The following signatures (from keys)"
              + " could not be verified: "
              + formatMissingSignatures(
              signaturesRequiredForTheseKeysCheckList));
    }
  }

  private String formatMissingSignatures(
      final Set<String> signaturesRequiredForTheseKeysCheckList) {

    final StringBuilder missingSignatures = new StringBuilder();

    for (final String uid : signaturesRequiredForTheseKeysCheckList) {
      if (missingSignatures.length() != 0) {
        missingSignatures.append(", ");
      }
      missingSignatures.append(uid);
    }
    return missingSignatures.toString();
  }

  @Override
  public boolean isRequireSignatureCheck() {
    return true;
  }
}

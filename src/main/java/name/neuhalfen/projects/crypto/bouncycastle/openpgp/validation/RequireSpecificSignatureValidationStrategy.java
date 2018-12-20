package name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation;


import static java.util.Objects.requireNonNull;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationHelper.knownKeysWithGoodSignatures;

import java.io.IOException;
import java.security.SignatureException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignaturesMissingException.SetSemantics;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPSignatureList;

final class RequireSpecificSignatureValidationStrategy implements SignatureValidationStrategy {

  private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
      .getLogger(RequireSpecificSignatureValidationStrategy.class);

  private final Set<Long> signaturesRequiredForTheseKeys;

  /**
   * @param signaturesRequiredForTheseKeys Signatures for all keys are needed
   */
  RequireSpecificSignatureValidationStrategy(Collection<Long> signaturesRequiredForTheseKeys) {
    requireNonNull(signaturesRequiredForTheseKeys,
        "signaturesRequiredForTheseKeys must not be null");
    this.signaturesRequiredForTheseKeys = new HashSet<>(signaturesRequiredForTheseKeys);
  }

  @Override
  @SuppressWarnings("PMD.CyclomaticComplexity")
  public void validateSignatures(PGPObjectFactory factory,
      Map<Long, PGPOnePassSignature> onePassSignatures) throws
      SignatureException, PGPException, IOException {

    requireNonNull(factory, "factory must not be null");
    requireNonNull(onePassSignatures, "onePassSignatures must not be null");

    // verify the signature
    final PGPSignatureList signatureList = extractPgpSignatures(factory);

    final Set<Long> keysWithGoodSignatures = knownKeysWithGoodSignatures(onePassSignatures,
        signatureList);

    // This is a bucket list of needed signatures. If we find a valid signature
    // we remove it from the bucket list. If all signatures are checked and the bucket list is
    // empty, we have all signatures we need.  If the list is NOT empty, it contains
    // all the keys for which we needed a signature but didn't get.
    final Set<Long> signaturesRequiredForTheseKeysCheckList = new HashSet<>(
        signaturesRequiredForTheseKeys);
    signaturesRequiredForTheseKeysCheckList.removeAll(keysWithGoodSignatures);

    final boolean successfullyVerified = signaturesRequiredForTheseKeysCheckList.isEmpty();

    if (successfullyVerified) {
      LOGGER.debug("Signature verification success");
    } else {
      throw createMissingSignaturesException(signaturesRequiredForTheseKeysCheckList);
    }
  }

  private PGPSignatureList extractPgpSignatures(final PGPObjectFactory factory)
      throws IOException, SignaturesMissingException {
    final PGPSignatureList signatureList = (PGPSignatureList) factory.nextObject();

    if (signatureList == null || signatureList.isEmpty()) {
      // This statement is not reached in normal flow
      // because decryption errs first when it does not find
      // the one pass signature before the data object.
      throw createMissingSignaturesException(signaturesRequiredForTheseKeys);
    }
    return signatureList;
  }


  private SignaturesMissingException createMissingSignaturesException(Set<Long> missingForKeyIds) {
    return new SignaturesMissingException(
        "Signature verification failed because all of the following signatures "
            + "(by keyId) are missing.",
        SignaturesMissingException.MissingSignature.fromKeyIds( //NOPMD: Demeter
            missingForKeyIds),
        SetSemantics.ALL_SIGNATURES_MISSING);
  }

  @Override
  public boolean isRequireSignatureCheck() {
    return true;
  }
}

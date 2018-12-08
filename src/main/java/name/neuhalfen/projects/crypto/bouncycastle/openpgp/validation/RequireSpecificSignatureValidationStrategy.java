package name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation;


import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.security.SignatureException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPSignature;
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
    final PGPSignatureList signatureList = (PGPSignatureList) factory.nextObject();

    if (signatureList == null || signatureList.isEmpty()) {
      // This statement is not reached in normal flow
      // because decryption errs first when it does not find
      // the one pass signature before the data object.
      throw new PGPException("No signatures found!");
    }

    // This is a bucket list of needed signatures. If we find a valid signature
    // we remove it from the bucket list. If all signatures are checked and the bucket list is
    // empty, we have all signatures we need.  If the list is NOT empty, it contains
    // all the keys for which we needed a signature but didn't get.
    final Set<Long> signaturesRequiredForTheseKeysCheckList = new HashSet<>(
        signaturesRequiredForTheseKeys);

    for (final PGPSignature messageSignature : signatureList) {
      final PGPOnePassSignature ops = onePassSignatures.get(messageSignature.getKeyID());

      final boolean isHasPubKeyForSignature = ops != null;
      if (isHasPubKeyForSignature) {
        final boolean isThisSignatureGood = ops.verify(messageSignature); // NOPMD : Demeter

        if (isThisSignatureGood) {
          LOGGER.debug(
              "Successful validated signature with key 0x{} because we have no matching public key",
              Long.toHexString(messageSignature.getKeyID()));
          // A valid signature: cross out from bucket list
          signaturesRequiredForTheseKeysCheckList.remove(messageSignature.getKeyID());
        }
      } else {
        LOGGER.debug(
            "Could not validated signature with key 0x{} because we have no matching public key",
            Long.toHexString(messageSignature.getKeyID()));
      }
    }

    final boolean successfullyVerified = signaturesRequiredForTheseKeysCheckList.isEmpty();

    if (successfullyVerified) {
      LOGGER.debug("Signature verification success");
    } else {
      final StringBuilder missingSignatures = new StringBuilder();
      for (final Long key : signaturesRequiredForTheseKeysCheckList) {
        if (missingSignatures.length() != 0) {
          missingSignatures.append(", ");
        }
        missingSignatures.append("0x");
        missingSignatures.append(Long.toHexString(key));
      }
      throw new SignatureException(
          "Signature verification failed! The following signatures (from keys) could not be verified: "
              + missingSignatures.toString());
    }
  }

  @Override
  public boolean isRequireSignatureCheck() {
    return true;
  }
}

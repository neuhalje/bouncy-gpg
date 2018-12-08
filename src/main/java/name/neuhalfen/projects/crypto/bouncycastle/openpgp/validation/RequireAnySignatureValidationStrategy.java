package name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation;


import java.io.IOException;
import java.security.SignatureException;
import java.util.Map;
import name.neuhalfen.projects.crypto.internal.Preconditions;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;

final class RequireAnySignatureValidationStrategy implements SignatureValidationStrategy {

  private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
      .getLogger(RequireAnySignatureValidationStrategy.class);

  @Override
  public void validateSignatures(PGPObjectFactory factory,
      Map<Long, PGPOnePassSignature> onePassSignatures) throws
      SignatureException, PGPException, IOException {

    Preconditions.checkNotNull(factory, "factory must not be null");
    Preconditions.checkNotNull(onePassSignatures, "onePassSignatures must not be null");

    // verify the signature
    final PGPSignatureList signatureList = (PGPSignatureList) factory.nextObject();

    if (signatureList == null || signatureList.isEmpty()) {
      // This statement is not reached in normal flow
      // because decryption errs first when it does not find
      // the one pass signature before the data object.
      throw new PGPException("No signatures found!");
    }

    boolean successfullyVerified = false;

    for (PGPSignature messageSignature : signatureList) {
      PGPOnePassSignature ops = onePassSignatures.get(messageSignature.getKeyID());

      final boolean isHasPubKeyForSignature = ops != null;
      if (isHasPubKeyForSignature) {
        final boolean isThisSignatureGood = ops.verify(messageSignature); // NOPMD: Demeter

        LOGGER.debug("{} validated signature with key 0x{}",
            isThisSignatureGood ? "Successfully" : "Failed to",
            Long.toHexString(messageSignature.getKeyID()));
        successfullyVerified |= isThisSignatureGood;
      } else {
        LOGGER.debug(
            "Could not validated signature with key 0x{} because we have no matching public key",
            Long.toHexString(messageSignature.getKeyID()));
      }
    }

    if (successfullyVerified) {
      LOGGER.debug("Signature verification success");
    } else {
      throw new SignatureException("Signature verification failed!");
    }
  }

  @Override
  public boolean isRequireSignatureCheck() {
    return true;
  }
}

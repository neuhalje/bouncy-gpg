package name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;

final class SignatureValidationHelper {

  private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
      .getLogger(SignatureValidationHelper.class);

  private SignatureValidationHelper() { /* no instances */}

  public static Set<Long> knownKeysWithGoodSignatures(
      final Map<Long, PGPOnePassSignature> onePassSignatures,
      final PGPSignatureList signatureList) throws PGPException {

    final Set<Long> goodSignatures = new HashSet<>();

    for (final PGPSignature messageSignature : signatureList) {
      final PGPOnePassSignature ops = onePassSignatures.get(messageSignature.getKeyID());

      final boolean isHasPubKeyForSignature = ops != null;
      if (isHasPubKeyForSignature) {
        final boolean isThisSignatureGood = ops.verify(messageSignature); // NOPMD : Demeter

        if (isThisSignatureGood) {
          LOGGER.debug(
              "Successful validated signature with key 0x{} because we have no matching public key",
              Long.toHexString(messageSignature.getKeyID()));
          goodSignatures.add(messageSignature.getKeyID());
        }
      } else {
        LOGGER.debug(
            "Could not validated signature with key 0x{} because we have no matching public key",
            Long.toHexString(messageSignature.getKeyID()));
      }
    }
    return goodSignatures;
  }

}

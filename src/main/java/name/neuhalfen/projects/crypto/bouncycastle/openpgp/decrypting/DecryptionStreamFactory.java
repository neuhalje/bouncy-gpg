package name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting;


import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.util.Iterator;
import javax.annotation.Nonnull;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.PGPUtilities;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationStrategies;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationStrategy;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;

/**
 * <p>Factory that creates a decrypting InputStream that wraps a ciphertext (GPG) steam
 * and decrypts it.
 * </p>
 * <p>After decryption of the stream the signature is verified in 'close'.</p>
 */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.AccessorMethodGeneration", "PMD.LawOfDemeter"})
public final class DecryptionStreamFactory {

  private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
      .getLogger(DecryptionStreamFactory.class);


  @Nonnull
  private final PGPContentVerifierBuilderProvider pgpContentVerifierBuilderProvider =
      new BcPGPContentVerifierBuilderProvider();

  @Nonnull
  private final KeyringConfig config;

  @Nonnull
  private final SignatureValidationStrategy signatureValidationStrategy;

  private DecryptionStreamFactory(final KeyringConfig config,
      final SignatureValidationStrategy signatureValidationStrategy) {
    this.signatureValidationStrategy = signatureValidationStrategy;
    this.config = config;
  }

  /**
   * <p>
   * Factory method for the DecryptionStreamFactory.
   * </p>
   * {@link SignatureValidationStrategies} provides several strategies.
   *
   * @param config keyring config.
   * @param signatureValidationStrategy how signatures are validated.
   *
   * @return factory instance
   *
   * @see name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationStrategies
   */
  public static DecryptionStreamFactory create(final KeyringConfig config,
      final SignatureValidationStrategy signatureValidationStrategy) {
    requireNonNull(config, "config must not be null");
    requireNonNull(signatureValidationStrategy,
        "signatureValidationStrategy must not be null");

    return new DecryptionStreamFactory(config, signatureValidationStrategy);
  }

  /**
   * Wrap the stream, return the plaintext stream.
   *
   * @param inputStream ciphertext
   *
   * @return plaintext stream
   *
   * @throws IOException io error
   * @throws NoSuchProviderException bouncy castle not registered?
   */
  public InputStream wrapWithDecryptAndVerify(InputStream inputStream)
      throws IOException, NoSuchProviderException {
    requireNonNull(inputStream, "inputStream must not be null");

    LOGGER.trace("Trying to decrypt and verify PGP Encryption.");

    try {
      final PGPObjectFactory factory = new PGPObjectFactory(PGPUtil.getDecoderStream(inputStream),
          config.getKeyFingerPrintCalculator());

      return nextDecryptedStream(factory, new SignatureValidatingInputStream.DecryptionState());

    } catch (PGPException e) {
      throw new IOException("Failure decrypting", e);
    }
  }

  /**
   * Handles PGP objects in decryption process by recursively calling itself.
   *
   * @param factory PGPObjectFactory to access the next objects, might be recreated within this
   *     method
   * @param state Decryption state, e.g. used for signature validation
   *
   * @throws PGPException the pGP exception
   * @throws IOException Signals that an I/O exception has occurred.
   */
  @SuppressWarnings({"PMD.ExcessiveMethodLength", "PMD.OnlyOneReturn",
      "PMD.AvoidInstantiatingObjectsInLoops", "PMD.CyclomaticComplexity"})
  private InputStream nextDecryptedStream(PGPObjectFactory factory,
      SignatureValidatingInputStream.DecryptionState state)
      throws PGPException, IOException {

    Object pgpObj;

    //
    while ((pgpObj = factory.nextObject()) != null) { //NOPMD

      if (pgpObj instanceof PGPEncryptedDataList) {
        LOGGER.trace("Found instance of PGPEncryptedDataList");
        final PGPEncryptedDataList enc = (PGPEncryptedDataList) pgpObj;
        final Iterator<?> encryptedDataObjects = enc.getEncryptedDataObjects();

        if (!encryptedDataObjects.hasNext()) {
          throw new PGPException("Decryption failed - No encrypted data found!");
        }
        //
        // find the secret key
        //
        PGPPrivateKey privateKey = null;
        PGPPublicKeyEncryptedData pbe = null; // NOPMD: must initialize pbe
        while (privateKey == null && encryptedDataObjects.hasNext()) {
          pbe = (PGPPublicKeyEncryptedData) encryptedDataObjects.next();
          privateKey = PGPUtilities.findSecretKey(config.getSecretKeyRings(), pbe.getKeyID(),
              config.decryptionSecretKeyPassphraseForSecretKeyId(pbe.getKeyID()));
        }

        if (privateKey == null) {
          // Wrong passphrases already trigger a throw in PGPUtilities.findSecretKey.
          throw new PGPException(
              "Decryption failed - No secret key was found in the key ring matching the public key"
                  + " used to encrypt the file, aborting");
        }

        // decrypt the data

        try(
                InputStream plainText = pbe
            .getDataStream(new BcPublicKeyDataDecryptorFactory(
                privateKey)) // NOPMD: AvoidInstantiatingObjectsInLoops
        )
        {
          final PGPObjectFactory nextFactory = new PGPObjectFactory(plainText,
                  new BcKeyFingerprintCalculator());// NOPMD: AvoidInstantiatingObjectsInLoops
          return nextDecryptedStream(nextFactory, state);  // NOPMD: OnlyOneReturn
        }
      } else if (pgpObj instanceof PGPCompressedData) {
        LOGGER.trace("Found instance of PGPCompressedData");
        final PGPObjectFactory nextFactory = new PGPObjectFactory(
            ((PGPCompressedData) pgpObj).getDataStream(), config.getKeyFingerPrintCalculator());
        return nextDecryptedStream(nextFactory, state);   // NOPMD: OnlyOneReturn
      } else if (pgpObj instanceof PGPOnePassSignatureList) {
        LOGGER.trace("Found instance of PGPOnePassSignatureList");

        if (signatureValidationStrategy.isRequireSignatureCheck()) {

          state.setSignatureFactory(factory);

          // verify the signature
          final PGPOnePassSignatureList onePassSignatures = (PGPOnePassSignatureList) pgpObj;
          for (final PGPOnePassSignature signature : onePassSignatures) {
            final PGPPublicKey pubKey = config.getPublicKeyRings()
                .getPublicKey(signature.getKeyID());

            final boolean isHavePublicKeyForSignatureInKeyring = pubKey != null;
            if (isHavePublicKeyForSignatureInKeyring) {
              if (LOGGER.isTraceEnabled()) {
                LOGGER.trace(
                    "Signature found, and the matching public key '0x{}' was also found "
                        + "in the keyring.",
                    Long.toHexString(signature.getKeyID()));
              }
              signature.init(pgpContentVerifierBuilderProvider, pubKey);
              state.addSignature(signature);
            } else {
              LOGGER.info("Found signature but public key '0x{}' was not found in the keyring.",
                  Long.toHexString(signature.getKeyID()));
            }
          }
          if (!state.hasVerifiableSignatures()) {
            throw new PGPException(
                "Signature checking is required but none of the public keys used to sign the data "
                    + "were found in the keyring'!");
          }
        } else {
          LOGGER.trace("Signature check disabled - ignoring contained signature");
        }
      } else if (pgpObj instanceof PGPLiteralData) {
        LOGGER.trace("Found instance of PGPLiteralData");

        final InputStream literalDataInputStream = ((PGPLiteralData) pgpObj).getInputStream();

        if (signatureValidationStrategy.isRequireSignatureCheck()) {
          if (!state.hasVerifiableSignatures()) {
            throw new PGPException("Signature checking is required but message was not signed!");
          }
          return new SignatureValidatingInputStream(
              literalDataInputStream,
              state, signatureValidationStrategy);  // NOPMD: OnlyOneReturn

        } else {
          return literalDataInputStream; // NOPMD: OnlyOneReturn
        }
      } else { // keep on searching...
        if (LOGGER.isTraceEnabled()) {
          LOGGER.trace("Skipping pgp Object of Type {}", pgpObj.getClass().getSimpleName());
        }
      }
    }
    throw new PGPException("No data found");
  }
}
package name.neuhalfen.projects.crypto.symmetric.keygeneration;


import static java.nio.charset.StandardCharsets.UTF_8;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.derivation.KeyDerivationFunction;

public class DerivedKeyGenerator {


  private final KeyDerivationFunction kdFwithMasterKeyMixin;
  @Nullable
  private final byte[] salt;
  private final static int MAXIMUM_CONTEXT_ELEMENT_LENGTH = 0xffff;


  /**
   * @param salt (from rfc5869): Ideally, the salt value is a random (or pseudorandom) string of the
   * length HashLen (HashLen = 256/8 = 32 bytes). Yet, even a salt value of less quality (shorter in
   * size or with limited entropy) may still make a significant contribution to the security of the
   * output keying material; designers of applications are therefore encouraged to provide salt
   * values to HKDF if such values can be obtained by the application.
   */
  public DerivedKeyGenerator(KeyDerivationFunction kdFwithMasterKeyMixin, @Nullable byte[] salt) {
    this.kdFwithMasterKeyMixin = kdFwithMasterKeyMixin;
    this.salt = salt;
  }

  /**
   * @param contextName contextName and idUniqueInContext are combined to create the 'info' value
   * from rfc5869: (from rfc5869): While the 'info' value is optional in the definition of HKDF, it
   * is often of great importance in applications.  Its main objective is to bind the derived key
   * material to application- and context-specific information.  For example, 'info' may contain a
   * protocol number, algorithm identifiers, user identities, etc.  In particular, it may prevent
   * the derivation of the same keying material for different contexts (when the same input key
   * material (IKM) is used in such different contexts). It may also accommodate additional inputs
   * to the key expansion part, if so desired (e.g., an application may want to bind the key
   * material to its length L, thus making L part of the 'info' field). <p> There is one technical
   * requirement from 'info': it should be independent of the input key material value IKM (the
   * masterkey).
   * @param idUniqueInContext contextName and idUniqueInContext are combined to create the 'info'
   * value from rfc5869.
   * @param desiredKeyLengthBytes the length of the derived key in bytes (e.g. 16 for AES-128)
   *
   * @return A derived key of length  desiredKeyLengthBytes
   */
  public byte[] deriveKey(final String contextName, final String idUniqueInContext,
      final String recordVersion,
      int desiredKeyLengthBytes) throws GeneralSecurityException {
    final String derivedKeyIdentifierStr = constructDerivedKeyIdentifier(contextName,
        idUniqueInContext, recordVersion);
    final byte[] derivedKeyIdentifier = byteRepresentationOf(derivedKeyIdentifierStr);

    final byte[] derivedKey = kdFwithMasterKeyMixin
        .deriveKey(salt, derivedKeyIdentifier, desiredKeyLengthBytes * 8);

    return derivedKey;
  }


  @SuppressWarnings({"PMD.AvoidReassigningParameters", "PMD.DefaultPackage"})
  public String constructDerivedKeyIdentifier(String contextName, final String idUniqueInContext,
      final String recordVersion) {
    if (contextName == null) {
      contextName = "";
    }
    if (contextName.length() > MAXIMUM_CONTEXT_ELEMENT_LENGTH) {
      throw new IllegalArgumentException(
          "ContextName must be <= " + MAXIMUM_CONTEXT_ELEMENT_LENGTH + " chars");
    }
    if (idUniqueInContext == null || idUniqueInContext.isEmpty()) {
      throw new IllegalArgumentException("idUniqueInContext must be set");
    }
    if (idUniqueInContext.length() > MAXIMUM_CONTEXT_ELEMENT_LENGTH) {
      throw new IllegalArgumentException(
          "idUniqueInContext must be <= " + MAXIMUM_CONTEXT_ELEMENT_LENGTH + " chars");
    }

    if (recordVersion == null || recordVersion.isEmpty()) {
      throw new IllegalArgumentException("recordVersion must be set");
    }
    if (recordVersion.length() > MAXIMUM_CONTEXT_ELEMENT_LENGTH) {
      throw new IllegalArgumentException(
          "recordVersion must be <= " + MAXIMUM_CONTEXT_ELEMENT_LENGTH + " chars");
    }

    return String
        .format("%04x:%s:%04x:%s:%04x:%s", contextName.length(), contextName,
            idUniqueInContext.length(),
            idUniqueInContext, recordVersion.length(), recordVersion);
  }

  /*
   * in: String
   * out: byte[] of the byte representation of the UTF-8 string
   */
  @SuppressWarnings("PMD.LawOfDemeter")
  private byte[] byteRepresentationOf(String identifier) {
    final ByteBuffer buffer = UTF_8.encode(CharBuffer.wrap(identifier));
    final byte[] identifierByteRepresentation = new byte[buffer.limit()];
    buffer.get(identifierByteRepresentation);
    return identifierByteRepresentation;
  }
}

package name.neuhalfen.projects.crypto.symmetric.keygeneration;


import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.derivation.KeyDerivationFunction;

public class DerivedKeyGenerator {


  private final KeyDerivationFunction kdFwithMasterKeyMixin;


  public DerivedKeyGenerator(KeyDerivationFunction kdFwithMasterKeyMixin) {
    this.kdFwithMasterKeyMixin = kdFwithMasterKeyMixin;
  }

  /**
   * @param salt (from rfc5869): Ideally, the salt value is a random (or pseudorandom) string of the
   * length HashLen (HashLen = 256/8 = 32 bytes). Yet, even a salt value of less quality (shorter in
   * size or with limited entropy) may still make a significant contribution to the security of the
   * output keying material; designers of applications are therefore encouraged to provide salt
   * values to HKDF if such values can be obtained by the application.
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
   * @return A derived key of length  desiredKeyLengthBytes
   */
  public byte[] deriveKey(byte[] salt, final String contextName, final String idUniqueInContext,
      int desiredKeyLengthBytes) throws GeneralSecurityException {
    final String derivedKeyIdentifierStr = constructDerivedKeyIdentifier(contextName,
        idUniqueInContext);
    final byte[] derivedKeyIdentifier = byteRepresentationOf(derivedKeyIdentifierStr);

    final byte[] derivedKey = kdFwithMasterKeyMixin
        .deriveKey(salt, derivedKeyIdentifier, desiredKeyLengthBytes);

    return derivedKey;
  }


  @SuppressWarnings({"PMD.AvoidReassigningParameters","PMD.DefaultPackage"})
  String constructDerivedKeyIdentifier(String contextName, final String idUniqueInContext) {
    if (contextName == null) {
      contextName = "";
    }
    if (contextName.length() > 0xffff) {
      throw new IllegalArgumentException("ContextName must be <= 0xffff chars");
    }
    if (idUniqueInContext == null || idUniqueInContext.isEmpty()) {
      throw new IllegalArgumentException("idUniqueInContext must be set");
    }

    return String.format("%4x:%s:%s", contextName.length(), contextName, idUniqueInContext);
  }


  /*
   * in: String
   * out: byte[] of the byte representation of the UTF-8 string
   */
  private byte[] byteRepresentationOf(String identifier) {
    final ByteBuffer buffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(identifier));
    final byte[] identifierByteRepresentation = new byte[buffer.limit()];
    buffer.get(identifierByteRepresentation);
    return identifierByteRepresentation;
  }
}

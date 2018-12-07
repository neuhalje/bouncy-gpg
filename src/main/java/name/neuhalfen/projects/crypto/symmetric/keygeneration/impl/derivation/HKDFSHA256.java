package name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.derivation;


import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.internal.Preconditions;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

/**
 * Implements HKDF with SHA256 as hashing algorithm. The master key ("IKM - input key material") is
 * stored as part of the instance.
 * s
 * <ul>
 * <li><a href="https://en.wikipedia.org/wiki/Key_derivation_function">Key  derivation
 * function</a>  on Wikipedia. </li>
 * <li> <a href="https://tools.ietf.org/html/rfc5869">RFC 5869 HMAC-based Extract-and-Expand Key
 * Derivation Function (HKDF)</a> </li>
 * <li> <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf">NIST
 * Recommendation for Key Derivation through Extraction-then-Expansion, Special Publication
 * SP800-56C</a> </li>
 * <li> <a href="https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR02102/BSI-TR-02102.pdf?__blob=publicationFile">BSI
 * TR-02102-1  Kryptographische Verfahren: Empfehlungen und Schlussellaengen</a></li>
 * </ul>
 */
public class HKDFSHA256 implements KeyDerivationFunction {

  private final byte[] masterKey;

  public HKDFSHA256(byte[] masterKey) {
    Preconditions.checkNotNull(masterKey, "masterKey must not be null");

    this.masterKey = Arrays.copyOf(masterKey, masterKey.length);
  }

  @Override
  public byte[] deriveKey(@Nullable byte[] salt, byte[] info, int desiredKeyLengthInBits)
      throws GeneralSecurityException {

    Preconditions.checkNotNull(info, "info must not be null");
    Preconditions.checkArgument(desiredKeyLengthInBits % 8 == 0,
        "desiredKeyLengthInBits must be multiple of 8 but is " + desiredKeyLengthInBits);

    int desiredKeyLengthInBytes = desiredKeyLengthInBits / 8;

    final DerivationParameters derivationParameters = new HKDFParameters(masterKey, salt, info);

    final SHA256Digest digest = new SHA256Digest();
    final HKDFBytesGenerator hkdfGenerator = new HKDFBytesGenerator(digest);

    hkdfGenerator.init(derivationParameters);

    final byte[] hkdf = new byte[desiredKeyLengthInBytes];

    final int generatedKeyLength = hkdfGenerator.generateBytes(hkdf, 0, hkdf.length);

    if (generatedKeyLength != desiredKeyLengthInBytes) {
      throw new GeneralSecurityException(String
          .format("Failed to derive key. Expected %d bytes, generated %d ", desiredKeyLengthInBytes,
              generatedKeyLength));
    }
    return hkdf;
  }

}

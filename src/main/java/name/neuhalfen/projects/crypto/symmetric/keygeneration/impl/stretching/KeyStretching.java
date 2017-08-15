package name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.stretching;

import java.security.GeneralSecurityException;

/**
 * Encapsulates a key derivation function that stretches (strengthens) the key.
 *
 * Examples for key stretching functions are SCrypt and PBKDF.
 *
 * <p>
 * An implementation *instance*:
 * <p>
 * * must derive deterministically (always return the same key for the same input)
 * * may include other data in the derived key (e.g. an inherent salt)
 * <p>
 * Different *instances* may:
 * * derive a different key
 *
 * Further Reading:
 *  * <a href="https://en.wikipedia.org/wiki/Key_stretching">Key stretching</a> on Wikipedia.
 *  * <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf">NIST Special Publication 800-132: Recommendation for Password-Based Key Derivation</a>
 *  * <a href="https://en.wikipedia.org/wiki/Key_derivation_function">Key derivation function</a>  on Wikipedia.
 */
public interface KeyStretching {
    byte[] strengthenKey(byte[] salt, byte[] keyToStrengthen, int desiredKeyLengthInBits) throws GeneralSecurityException;

}

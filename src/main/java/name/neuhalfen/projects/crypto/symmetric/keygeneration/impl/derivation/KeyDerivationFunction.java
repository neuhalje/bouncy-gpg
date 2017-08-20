package name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.derivation;

import java.security.GeneralSecurityException;

public interface KeyDerivationFunction {

  byte[] deriveKey(byte[] salt, byte[] info, int desiredKeyLength) throws GeneralSecurityException;
}

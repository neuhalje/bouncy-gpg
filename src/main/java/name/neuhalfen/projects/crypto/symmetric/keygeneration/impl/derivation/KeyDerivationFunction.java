package name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.derivation;

import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

public interface KeyDerivationFunction {

  byte[] deriveKey(@Nullable byte[] salt, byte[] info, int desiredKeyLengthInBits)
      throws GeneralSecurityException;
}

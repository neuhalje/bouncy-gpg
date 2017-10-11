package name.neuhalfen.projects.crypto.symmetric.keygeneration;


import java.util.Arrays;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.derivation.HKDFSHA256;
import name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.derivation.KeyDerivationFunction;

@SuppressWarnings({"PMD.AccessorClassGeneration"})
public final class DerivedKeyGeneratorFactory {

  private DerivedKeyGeneratorFactory() {
  }

  public static WithMasterKey fromInputKey(byte[] key) {
    return new WithMasterKey(key);
  }

  public final static class WithMasterKey {

    private final byte[] key;

    private WithMasterKey(byte[] key) {
      if (key == null) {
        throw new IllegalArgumentException("key must not be null");
      }
      this.key = Arrays.copyOf(key, key.length);
    }


    public WithSalt andSalt(byte[] salt) {
      if (salt == null) {
        throw new IllegalArgumentException("salt must not be null");
      }
      return new WithSalt(salt);
    }

    public WithSalt withoutSalt() {
      return new WithSalt();
    }

    public final class WithSalt {

      @Nullable
      private final byte[] salt;

      @SuppressWarnings("PMD.NullAssignment")
      private WithSalt() {
        this.salt = null;
      }

      private WithSalt(byte[] salt) {
        this.salt = Arrays.copyOf(salt, salt.length);
      }

      @SuppressWarnings("PMD.AccessorMethodGeneration")
      public final DerivedKeyGenerator withHKDFsha256() {
        KeyDerivationFunction kdf = new HKDFSHA256(key);
        return new DerivedKeyGenerator(kdf, salt);
      }
    }
  }
}

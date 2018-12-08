package name.neuhalfen.projects.crypto.symmetric.keygeneration;


import java.util.Arrays;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.internal.Preconditions;
import name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.derivation.HKDFSHA256;
import name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.derivation.KeyDerivationFunction;

@SuppressWarnings({"PMD.AccessorClassGeneration","PMD.ClassNamingConventions"})
public final class DerivedKeyGeneratorFactory {

  private DerivedKeyGeneratorFactory() {
  }

  public static WithMasterKey fromInputKey(byte[] key) {
    return new WithMasterKey(key);
  }

  public final static class WithMasterKey {

    private final byte[] key;

    private WithMasterKey(byte[] key) {
      Preconditions.checkNotNull(key, "key must not be null");
      Preconditions.checkArgument(key.length > 0, "key must not be empty");

      this.key = Arrays.copyOf(key, key.length);
    }


    public WithSalt andSalt(byte[] salt) {
      Preconditions.checkNotNull(key, "salt must not be null");
      Preconditions.checkArgument(salt.length > 0, "salt must not be empty");

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

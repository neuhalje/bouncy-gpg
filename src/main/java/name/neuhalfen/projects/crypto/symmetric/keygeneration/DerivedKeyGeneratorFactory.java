package name.neuhalfen.projects.crypto.symmetric.keygeneration;


import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.derivation.HKDFSHA256;
import name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.derivation.KeyDerivationFunction;

public class DerivedKeyGeneratorFactory {


  public final static WithMasterKey fromInputKey(byte[] key) {
    return new WithMasterKey(key);
  }

  public final static class WithMasterKey {

    private final byte[] key;

    private WithMasterKey(byte[] key) {
      this.key = key;
    }


    public WithSalt andSalt(byte[] salt) {
      return new WithSalt(salt);
    }

    public WithSalt withoutSalt() {
      return new WithSalt();
    }

    public final class WithSalt {

      @Nullable
      private final byte[] salt;

      private WithSalt() {
        this.salt = null;
      }

      private WithSalt(byte[] salt) {
        this.salt = salt;
      }


      public final DerivedKeyGenerator withHKDFsha256() {
        KeyDerivationFunction kdf = new HKDFSHA256(key);
        return new DerivedKeyGenerator(kdf, salt);
      }
    }
  }
}

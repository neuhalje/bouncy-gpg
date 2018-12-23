package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation;

import static java.util.Objects.requireNonNull;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.KeyType;

public class KeySpecBuilder {

  private KeySpecBuilder() {/* utility only */}

  public static KeySpecBuilderInterface newSpec(KeyType type) {
    requireNonNull(type, "type must not be null");
    return new KeySpecBuilderImpl(type);
  }
}

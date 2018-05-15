package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPCompressionAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPHashAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPSymmetricEncryptionAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PublicKeySize;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PublicKeyType;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

@SuppressWarnings("PMD")
public class BuildPGPKeyGeneratorAPI {

  private PublicKeyType keyType;
  private PublicKeySize.KeySize keySize;
  private String identity;
  private char[] passphrase;

  public Size<PublicKeySize.RSA> withRSAKeys() {
    this.keyType = PublicKeyType.RSA_GENERAL;
    return new Size<>();
  }

  public class Size<S extends PublicKeySize.KeySize> {

    private Size() {
    }

    public Identity ofSize(S size) {
      BuildPGPKeyGeneratorAPI.this.keySize = size;
      return new Identity();
    }
  }

  public class Identity {

    private Identity() {
    }

    public Passphrase forIdentity(String identity) {
      BuildPGPKeyGeneratorAPI.this.identity = identity;
      return new Passphrase();
    }
  }

  public class Passphrase {

    private Passphrase() {
    }

    public Build withPassphrase(String passphrase) {
      return withPassphrase(passphrase.toCharArray());
    }

    public Build withPassphrase(char[] passphrase) {
      BuildPGPKeyGeneratorAPI.this.passphrase = passphrase;
      return new Build();
    }

    public Build withoutPassphrase() {
      BuildPGPKeyGeneratorAPI.this.passphrase = null;
      return new Build();
    }
  }

  public class Build {

    private Build() {
    }

    public PGPKeyRingGenerator build()
        throws NoSuchAlgorithmException, PGPException, NoSuchProviderException {
      KeyPairGenerator pbkcGenerator = KeyPairGenerator.getInstance(
          BuildPGPKeyGeneratorAPI.this.keyType.getAlgorithmName(),
          BouncyCastleProvider.PROVIDER_NAME);
      pbkcGenerator.initialize(BuildPGPKeyGeneratorAPI.this.keySize.getSize());

      // Underlying public-key-cryptography key pair
      KeyPair pbkcKeyPair = pbkcGenerator.generateKeyPair();

      // hash calculator
      PGPDigestCalculator calculator = new JcaPGPDigestCalculatorProviderBuilder()
          .setProvider(BouncyCastleProvider.PROVIDER_NAME)
          .build()
          .get(HashAlgorithmTags.SHA1);

      // Form PGP key pair
      PGPKeyPair pgpPair = new JcaPGPKeyPair(
          BuildPGPKeyGeneratorAPI.this.keyType.getId(),
          pbkcKeyPair, new Date());

      // Signer for creating self-signature
      PGPContentSignerBuilder signer = new JcaPGPContentSignerBuilder(
          pgpPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256);

      // Encryptor for encrypting the secret key
      PBESecretKeyEncryptor encryptor = passphrase == null ?
          null : // unencrypted key pair, otherwise AES-256 encrypted
          new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, calculator)
              .setProvider(BouncyCastleProvider.PROVIDER_NAME)
              .build(passphrase);

      // Mimic GnuPGs signature sub packets
      PGPSignatureSubpacketGenerator hashedSubPackets = new PGPSignatureSubpacketGenerator();

      // Key flags
      hashedSubPackets.setKeyFlags(true,
          KeyFlags.CERTIFY_OTHER
              | KeyFlags.SIGN_DATA
              | KeyFlags.ENCRYPT_COMMS
              | KeyFlags.ENCRYPT_STORAGE
              | KeyFlags.AUTHENTICATION);

      // Encryption Algorithms
      hashedSubPackets.setPreferredSymmetricAlgorithms(true, new int[]{
          PGPSymmetricEncryptionAlgorithms.AES_256.getAlgorithmId(),
          PGPSymmetricEncryptionAlgorithms.AES_192.getAlgorithmId(),
          PGPSymmetricEncryptionAlgorithms.AES_128.getAlgorithmId(),
          PGPSymmetricEncryptionAlgorithms.TRIPLE_DES.getAlgorithmId()
      });

      // Hash Algorithms
      hashedSubPackets.setPreferredHashAlgorithms(true, new int[]{
          PGPHashAlgorithms.SHA_512.getAlgorithmId(),
          PGPHashAlgorithms.SHA_384.getAlgorithmId(),
          PGPHashAlgorithms.SHA_256.getAlgorithmId(),
          PGPHashAlgorithms.SHA_224.getAlgorithmId(),
          PGPHashAlgorithms.SHA1.getAlgorithmId()
      });

      // Compression Algorithms
      hashedSubPackets.setPreferredCompressionAlgorithms(true, new int[]{
          PGPCompressionAlgorithms.ZLIB.getAlgorithmId(),
          PGPCompressionAlgorithms.BZIP2.getAlgorithmId(),
          PGPCompressionAlgorithms.ZIP.getAlgorithmId()
      });

      // Modification Detection
      hashedSubPackets.setFeature(true, Features.FEATURE_MODIFICATION_DETECTION);

      // Generator which the user can get the key pair from
      PGPKeyRingGenerator ringGenerator = new PGPKeyRingGenerator(
          PGPSignature.POSITIVE_CERTIFICATION, pgpPair,
          BuildPGPKeyGeneratorAPI.this.identity, calculator,
          hashedSubPackets.generate(), null, signer, encryptor);

      return ringGenerator;
    }
  }
}

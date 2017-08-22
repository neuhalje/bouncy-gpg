package name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting;


import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPAlgorithmSuite;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.PGPUtilities;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

public final class PGPEncryptingStream extends OutputStream {

  private final KeyringConfig config;
  private final PGPAlgorithmSuite algorithmSuite;
  private boolean isDoSign;
  /**
   * The signature uid.
   */
  private OutputStream encryptionDataStream;
  private PGPSignatureGenerator signatureGenerator;

  @Nullable
  private ArmoredOutputStream armoredOutputStream;
  private OutputStream outerEncryptionStream;
  private BCPGOutputStream compressionStream;
  private PGPLiteralDataGenerator encryptionDataStreamGenerator;
  private PGPCompressedDataGenerator compressionStreamGenerator;

  private PGPEncryptingStream(final KeyringConfig config, final PGPAlgorithmSuite algorithmSuite) {
    super();
    this.config = config;
    this.algorithmSuite = algorithmSuite;
  }

  //Return a stream that, when written plaintext into, writes the ciphertext into cipherTextSink.
  public static OutputStream create(final KeyringConfig config,
      final PGPAlgorithmSuite algorithmSuite,
      final String signingUid,
      final OutputStream cipherTextSink,
      final boolean armor,
      final PGPPublicKey pubEncKey)
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {

    if (config == null) {
      throw new IllegalArgumentException("No config");
    }

    if (cipherTextSink == null) {
      throw new IllegalArgumentException("no cipherTextSink");
    }

    if (pubEncKey == null) {
      throw new IllegalArgumentException("No pubEncKey");
    }

    if (!pubEncKey.isEncryptionKey()) {
      throw new PGPException(String
          .format("This public key (0x%x) is not suitable for encryption", pubEncKey.getKeyID()));
    }

    final PGPEncryptingStream encryptingStream = new PGPEncryptingStream(config, algorithmSuite);
    encryptingStream.setup(cipherTextSink, signingUid, pubEncKey, armor);
    return encryptingStream;
  }


  /**
   * @param cipherTextSink Where the ciphertext goes
   * @param signingUid Sign with this uid. null: do not sign
   * @param pubEncKey the pub enc key
   * @param armor if OutputStream should be "armored", that means base64 encoded
   * @throws IOException Signals that an I/O exception has occurred.
   * @throws PGPException the pGP exception {@link org.bouncycastle.bcpg.HashAlgorithmTags} {@link
   * org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags}
   */
  @SuppressWarnings("PMD.LawOfDemeter")
  private void setup(final OutputStream cipherTextSink,
      @Nullable final String signingUid,
      final PGPPublicKey pubEncKey,
      final boolean armor) throws
      IOException, PGPException {
    isDoSign = (signingUid != null);

    final OutputStream sink;
    if (armor) {
      this.armoredOutputStream = new ArmoredOutputStream(cipherTextSink);
      sink = this.armoredOutputStream;
    } else {
      sink = cipherTextSink;
    }

    final BcPGPDataEncryptorBuilder dataEncryptorBuilder = new BcPGPDataEncryptorBuilder(
        algorithmSuite.getSymmetricEncryptionAlgorithmCode().getAlgorithmId());
    dataEncryptorBuilder.setWithIntegrityPacket(true);

    final PGPEncryptedDataGenerator cPk =
        new PGPEncryptedDataGenerator(dataEncryptorBuilder);

    cPk.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(pubEncKey));

    // this wraps the output stream in an encrypting output stream
    outerEncryptionStream = cPk.open(sink, new byte[1 << 16]);

    if (isDoSign) {
      final PGPSecretKey pgpSec = PGPUtilities
          .extractSecretSigningKeyFromKeyrings(config.getSecretKeyRings(), signingUid);

      final PGPPrivateKey pgpPrivKey = PGPUtilities.extractPrivateKey(pgpSec,
          config.decryptionSecretKeyPassphraseForSecretKeyId(pgpSec.getKeyID()));
      signatureGenerator = new PGPSignatureGenerator(
          new BcPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(),
              algorithmSuite.getHashAlgorithmCode().getAlgorithmId()));

      signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

      final Iterator<?> userIDs = pgpSec.getPublicKey().getUserIDs();
      if (userIDs.hasNext())

      {
        final PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

        spGen.setSignerUserID(false, (String) userIDs.next());
        signatureGenerator.setHashedSubpackets(spGen.generate());
      }
    }

    compressionStreamGenerator = new PGPCompressedDataGenerator(
        algorithmSuite.getCompressionEncryptionAlgorithmCode().getAlgorithmId());
    compressionStream = new BCPGOutputStream(
        compressionStreamGenerator.open(outerEncryptionStream));

    if (isDoSign) {
      signatureGenerator.generateOnePassVersion(false).encode(compressionStream);
    }

    encryptionDataStreamGenerator = new PGPLiteralDataGenerator();
    encryptionDataStream = encryptionDataStreamGenerator
        .open(compressionStream, PGPLiteralData.BINARY, "", new Date(), new byte[1 << 16]);
  }

  @Override
  public void write(int data) throws IOException {
    encryptionDataStream.write(data);

    if (isDoSign) {
      final byte asByte = (byte) (data & 0xff);
      signatureGenerator.update(asByte);
    }
  }


  @Override
  public void write(byte[] buffer) throws IOException {
    write(buffer, 0, buffer.length);
  }


  @Override
  public void write(byte[] buffer, int off, int len) throws IOException {
    encryptionDataStream.write(buffer, 0, len);
    if (isDoSign) {
      signatureGenerator.update(buffer, 0, len);
    }
  }

  @Override
  public void flush() throws IOException {
    encryptionDataStream.flush();
  }

  @Override
  public void close() throws IOException {
    encryptionDataStream.flush();
    encryptionDataStream.close();
    encryptionDataStreamGenerator.close();
    if (isDoSign) {

      try {
        signatureGenerator.generate().encode(compressionStream);
      } catch (PGPException e) {
        throw new IOException(e);
      }
    }
    compressionStreamGenerator.close();

    outerEncryptionStream.flush();
    outerEncryptionStream.close();

    if (armoredOutputStream != null) {
      armoredOutputStream.flush();
      armoredOutputStream.close();
    }
  }
}
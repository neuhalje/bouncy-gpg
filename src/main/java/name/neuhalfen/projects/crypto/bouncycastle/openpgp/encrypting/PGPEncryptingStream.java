package name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPAlgorithmSuite;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.shared.PGPUtilities;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;

public class PGPEncryptingStream extends OutputStream {
    /**
     * The Constant LOGGER.
     */
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(PGPEncryptingStream.class);


    private final KeyringConfig config;
    private PGPAlgorithmSuite algorithmSuite;

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

    PGPEncryptingStream(final KeyringConfig config, final PGPAlgorithmSuite algorithmSuite) throws IOException {
        this.config = config;
        this.algorithmSuite = algorithmSuite;
    }

    //Return a stream that, when written plaintext into, writes the ciphertext into cipherTextSink.
    public static OutputStream create(final KeyringConfig config,
                                      final PGPAlgorithmSuite algorithmSuite,
                                      final String signingUid,
                                      final OutputStream cipherTextSink,
                                      final boolean armor,
                                      final PGPPublicKey pubEncKey) throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {

        if (config == null) {
            throw new NullPointerException("No config");
        }

        if (cipherTextSink == null) {
            throw new NullPointerException("no cipherTextSink");
        }

        if (pubEncKey == null) {
            throw new NullPointerException("No pubEncKey");
        }

        if (!pubEncKey.isEncryptionKey()) {
            throw new PGPException(String.format("This public key (0x%x) is not suitable for encryption", pubEncKey.getKeyID()));
        }



        final PGPEncryptingStream encryptingStream = new PGPEncryptingStream(config, algorithmSuite);
        encryptingStream.setup(cipherTextSink, signingUid, pubEncKey, armor);
        return encryptingStream;
    }


    /**
     * @param cipherTextSink Where the ciphertext goes
     * @param pubEncKey      the pub enc key
     * @param armor          if OutputStream should be "armored", that means base64 encoded
     * @throws IOException              Signals that an I/O exception has occurred.
     * @throws NoSuchAlgorithmException the no such algorithm exception
     * @throws NoSuchProviderException  the no such provider exception
     * @throws PGPException             the pGP exception
     * @throws SignatureException       the signature exception
     *                                  {@link org.bouncycastle.bcpg.HashAlgorithmTags}
     *                                  {@link org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags}
     */
    protected void setup(final OutputStream cipherTextSink,
                         final String signingUid,
                         final PGPPublicKey pubEncKey,
                         final boolean armor) throws
            IOException, NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException {

        final OutputStream sink;
        if (armor) {
            this.armoredOutputStream = new ArmoredOutputStream(cipherTextSink);
            sink = this.armoredOutputStream;
        } else {
            sink = cipherTextSink;
        }

        final BcPGPDataEncryptorBuilder dataEncryptorBuilder = new BcPGPDataEncryptorBuilder(algorithmSuite.getSymmetricEncryptionAlgorithmCode().id);
        dataEncryptorBuilder.setWithIntegrityPacket(true);

        final PGPEncryptedDataGenerator cPk =
                new PGPEncryptedDataGenerator(dataEncryptorBuilder);


        cPk.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(pubEncKey));

        // this wraps the output stream in an encrypting output stream
        outerEncryptionStream = cPk.open(sink, new byte[1 << 16]);

        final PGPSecretKey pgpSec = PGPUtilities.extractSecretSigningKeyFromKeyrings(config.getSecretKeyRings(), signingUid);

        final PGPPrivateKey pgpPrivKey = PGPUtilities.extractPrivateKey(pgpSec, config.decryptionSecretKeyPassphraseForSecretKeyId(pgpSec.getKeyID()));
        signatureGenerator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), algorithmSuite.getHashAlgorithmCode().id));


        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

        final Iterator<?> it = pgpSec.getPublicKey().getUserIDs();
        if (it.hasNext())

        {
            final PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

            spGen.setSignerUserID(false, (String) it.next());
            signatureGenerator.setHashedSubpackets(spGen.generate());
        }

        compressionStreamGenerator = new PGPCompressedDataGenerator(algorithmSuite.getCompressionEncryptionAlgorithmCode().id);
        compressionStream = new BCPGOutputStream(compressionStreamGenerator.open(outerEncryptionStream));

        signatureGenerator.generateOnePassVersion(false).encode(compressionStream);

        encryptionDataStreamGenerator = new PGPLiteralDataGenerator();
        encryptionDataStream = encryptionDataStreamGenerator.open(compressionStream, PGPLiteralData.BINARY, "", new Date(), new byte[1 << 16]);
    }

    @Override
    public void write(int b) throws IOException {
        encryptionDataStream.write(b);
        final byte asByte = (byte) (b & 0xff);
        signatureGenerator.update(asByte);
    }


    @Override
    public void write(byte[] buffer) throws IOException {
        write(buffer, 0, buffer.length);
    }


    @Override
    public void write(byte[] buffer, int off, int len) throws IOException {
        encryptionDataStream.write(buffer, 0, len);
        signatureGenerator.update(buffer, 0, len);
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
        try {
            signatureGenerator.generate().encode(compressionStream);
        } catch (PGPException e) {
            throw new IOException(e);
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
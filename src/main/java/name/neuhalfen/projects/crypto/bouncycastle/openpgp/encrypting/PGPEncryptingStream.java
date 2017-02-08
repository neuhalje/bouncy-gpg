package name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.KeyringConfigCallback;
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

    /**
     * The signature uid.
     */
    private final String signatureUid;

    /**
     * The encryption public key ring.
     */
    private final PGPPublicKeyRing encryptionPublicKeyRing;

    /**
     * code for the hash algorithm used for signing according to {@link org.bouncycastle.bcpg.HashAlgorithmTags}.
     */
    private final int hashAlgorithmCode;

    /**
     * code for the algorithm used for symmetric encryption according to
     * {@link org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags}.
     */
    private final int symmetricEncryptionAlgorithmCode;

    private OutputStream encryptionDataStream;
    private PGPSignatureGenerator signatureGenerator;

    @Nullable
    private ArmoredOutputStream armoredOutputStream;
    private OutputStream outerEncryptionStream;
    private BCPGOutputStream compressionStream;
    private PGPLiteralDataGenerator encryptionDataStreamGenerator;
    private PGPCompressedDataGenerator compressionStreamGenerator;

    PGPEncryptingStream(final EncryptionConfig config) throws IOException {


        try {

            this.signatureUid = config.getSignatureSecretKeyId();

            this.encryptionPublicKeyRing =
                    PGPUtilities.extractPublicKeyRingForUserId(config.getEncryptionPublicKeyId(), config.getPublicKeyRings());

            this.hashAlgorithmCode = config.getPgpHashAlgorithmCode();
            this.symmetricEncryptionAlgorithmCode = config.getPgpSymmetricEncryptionAlgorithmCode();
        } catch (PGPException e) {
            throw new RuntimeException("Failed to construct EncryptWithOpenPGP", e);
        }
        this.config = config.getConfig();
    }

    //Return a stream that, when written plaintext into, writes the ciphertext into cipherTextSink.
    public static OutputStream create(final EncryptionConfig config,
                                      final OutputStream cipherTextSink,
                                      final boolean armor,
                                      final PGPPublicKey pubEncKey,
                                      final boolean withIntegrityCheck,
                                      final int hashAlgorithmCode,
                                      final int symmetricEncryptionAlgorithmCode,
                                      final KeyringConfigCallback passphraseCallback) throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {

        final PGPEncryptingStream encryptingStream = new PGPEncryptingStream(config);
        encryptingStream.setup(cipherTextSink, pubEncKey, armor, withIntegrityCheck, hashAlgorithmCode, symmetricEncryptionAlgorithmCode, passphraseCallback);
        return encryptingStream;
    }


    /**
     * @param cipherTextSink                   Where the ciphertext goes
     * @param pubEncKey                        the pub enc key
     * @param armor                            if OutputStream should be "armored", that means base64 encoded
     * @param withIntegrityCheck               the with integrity check
     * @param hashAlgorithmCode                code for the hash algorithm used for signing according to
     * @param symmetricEncryptionAlgorithmCode code for the algorithm used for symmetric encryption according to
     * @throws IOException              Signals that an I/O exception has occurred.
     * @throws NoSuchAlgorithmException the no such algorithm exception
     * @throws NoSuchProviderException  the no such provider exception
     * @throws PGPException             the pGP exception
     * @throws SignatureException       the signature exception
     *                                  {@link org.bouncycastle.bcpg.HashAlgorithmTags}
     *                                  {@link org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags}
     */
    protected void setup(final OutputStream cipherTextSink,
                         final PGPPublicKey pubEncKey,
                         final boolean armor,
                         final boolean withIntegrityCheck,
                         final int hashAlgorithmCode,
                         final int symmetricEncryptionAlgorithmCode,
                         final KeyringConfigCallback passphraseCallback) throws
            IOException, NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException {

        final OutputStream sink;
        if (armor) {
            this.armoredOutputStream = new ArmoredOutputStream(cipherTextSink);
            sink = this.armoredOutputStream;
        } else {
            sink = cipherTextSink;
        }

        final BcPGPDataEncryptorBuilder dataEncryptorBuilder = new BcPGPDataEncryptorBuilder(symmetricEncryptionAlgorithmCode);
        dataEncryptorBuilder.setWithIntegrityPacket(withIntegrityCheck);

        final PGPEncryptedDataGenerator cPk =
                new PGPEncryptedDataGenerator(dataEncryptorBuilder);


        cPk.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(pubEncKey));

        // this wraps the output stream in an encrypting output stream
        outerEncryptionStream = cPk.open(sink, new byte[1 << 16]);

        final PGPSecretKey pgpSec = PGPUtilities.extractSecretSigningKeyFromKeyrings(config.getSecretKeyRings(), signatureUid);

        final PGPPrivateKey pgpPrivKey = PGPUtilities.extractPrivateKey(pgpSec, passphraseCallback.decryptionSecretKeyPassphraseForSecretKeyId(pgpSec.getKeyID()));
        signatureGenerator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), hashAlgorithmCode));


        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

        final Iterator<?> it = pgpSec.getPublicKey().getUserIDs();
        if (it.hasNext())

        {
            final PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

            spGen.setSignerUserID(false, (String) it.next());
            signatureGenerator.setHashedSubpackets(spGen.generate());
        }

        compressionStreamGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZLIB);
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
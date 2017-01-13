package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.DecryptWithOpenPGPInputStreamFactory;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.DecryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.StreamDecryption;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.StreamEncryption;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Takes a ZIP file, unpacks it in memory (streaming), and writes the files encrypted.
 * <p>
 * E.g. with a file  /tmp/my_zip.zip  created this way:
 * <p>
 * <verbatim>
 * # find .
 * README
 * dir_a/file1
 * dir_a/file2
 * dir_b/dir_b1/file3
 * <p>
 * zip -r /tmp/my_zip.zip .
 * <p>
 * </verbatim>
 * <p>
 * The class will unpack, an re-encrypt the following directory structure
 * <p>
 * <verbatim>
 * # find .
 * README.gpg
 * dir_a/file1.gpg
 * dir_a/file2.gpg
 * dir_b/dir_b1/file3.gpg
 * </verbatim>
 */
public class ReencryptExplodedZipSinglethread {

    /**
     * The Constant LOGGER.
     */
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(ReencryptExplodedZipSinglethread.class);

    public void explodeAndReencrypt(InputStream is, DecryptionConfig decryptionConfig, StreamEncryption target, File destRootDir) throws Exception {

        DecryptWithOpenPGPInputStreamFactory decription  = new DecryptWithOpenPGPInputStreamFactory(decryptionConfig);
        final InputStream plainTextStream = decription.wrapWithDecryptAndVerify(is);

        final ExplodeAndReencrypt explodeAndReencrypt = new ExplodeAndReencrypt(plainTextStream, target, destRootDir);
        explodeAndReencrypt.explodeAndReencrypt();
    }
}


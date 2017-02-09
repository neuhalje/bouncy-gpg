package name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms;

import org.bouncycastle.crypto.tls.HashAlgorithm;


public enum PGPHashAlgorithms {
    NONE(HashAlgorithm.none),
    MD5(HashAlgorithm.md5),
    SHA1(HashAlgorithm.sha1),
    SHA_224(HashAlgorithm.sha224),
    SHA_256(HashAlgorithm.sha256),
    SHA_384(HashAlgorithm.sha384),
    SHA_512(HashAlgorithm.sha512);

    public final int id;
    public final boolean insecure;

    PGPHashAlgorithms(int id) {
        this(id, false);
    }

    PGPHashAlgorithms(int id, boolean insecure) {
        this.id = id;
        this.insecure = insecure;
    }
}

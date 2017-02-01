package name.neuhalfen.projects.crypto.bouncycastle.openpgp;


public class BouncyGPG {

    public static BuildDecryptionInputStreamAPI decrypt() {
        return new BuildDecryptionInputStreamAPI();
    }

    public static BuildEncryptionOutputStreamAPI encryptToStream() {
        return new BuildEncryptionOutputStreamAPI();
    }

    public static BuildVerificationInputStreamAPI verifySignature() {
        return new BuildVerificationInputStreamAPI();
    }

}

package name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.stretching;


import name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.stretching.KeyStretching;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public class MasterKeyFromPasswordDerivation {

    public MasterKeyFromPasswordDerivation(KeyStretching stretching) {
        this.stretching = stretching;
    }


    private final KeyStretching stretching;

    public byte[] deriveKey(final String salt, final String masterPassword, int desiredKeyLengthBytes) throws GeneralSecurityException {

        final byte[] derivedKey = stretching.strengthenKey(byteRepresentationOf(salt), byteRepresentationOf(masterPassword), desiredKeyLengthBytes);

        return derivedKey;
    }

    public byte[] deriveKey(byte[] salt, final String masterPassword, int desiredKeyLengthBytes) throws GeneralSecurityException {

        final byte[] derivedKey = stretching.strengthenKey(salt, byteRepresentationOf(masterPassword), desiredKeyLengthBytes);

        return derivedKey;
    }

    public byte[] deriveKey(byte[] salt, final byte[] masterPassword, int desiredKeyLengthBytes) throws GeneralSecurityException {

        final byte[] derivedKey = stretching.strengthenKey(salt, masterPassword, desiredKeyLengthBytes);

        return derivedKey;
    }


    /*
     * in: String
     * out: byte[] of the byte representation of the UTF-8 string
     */
    private byte[] byteRepresentationOf(String identifier) {
        final ByteBuffer buffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(identifier));
        final byte[] identifierByteRepresentation = new byte[buffer.limit()];
        buffer.get(identifierByteRepresentation);
        return identifierByteRepresentation;
    }
}

package name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.stretching;

import org.bouncycastle.crypto.generators.SCrypt;

import java.io.Serializable;
import java.util.Objects;


public class SCryptKeyStretching implements KeyStretching {

    public static SCryptKeyStretching forConfig(SCryptKeyStretchingParameters cfg) {
        return new SCryptKeyStretching(cfg);
    }

    public SCryptKeyStretching(SCryptKeyStretchingParameters cfg) {
        this.cfg = cfg;
    }


    public final static class SCryptKeyStretchingParameters implements Serializable{

        /**
         * Generate a workload factor for sensitive ( ~10 seconds in 2017)
         * derivation.
         *
         * @return N:=2^21, r:=8, p:=1
         */
        public static SCryptKeyStretchingParameters forSensitiveStorage() {
            return new SCryptKeyStretchingParameters(1 << 21, 8, 1);
        }

        /**
         * Generate a workload factor for quick (~10ms in 2017)
         * derivation.
         * <p>
         * You can use this if the secret has a very high entropy.
         *
         * @return N:=2^12, r:=4, p:=1
         */
        public static SCryptKeyStretchingParameters forQuickDerivation() {
            return new SCryptKeyStretchingParameters(1 << 12, 4, 1);
        }


        /**
         * Generate a workload factor for quickest (~1ms in 2017)
         * derivation.
         * <p>
         * **Only use this if you REALLY know what you do.**
         * <p>
         * This brings effectively close-to-zero protection against brute force attacks.
         *
         * @return N:=2^8, r:=4, p:=1
         */
        public static SCryptKeyStretchingParameters forQuickestDerivation() {
            return new SCryptKeyStretchingParameters(1 << 8, 4, 1);
        }

        private final int N, r, p;

        public int getN() {
            return N;
        }

        public int getR() {
            return r;
        }

        public int getP() {
            return p;
        }

        public SCryptKeyStretchingParameters(int N, int r, int p) {
            this.N = N;
            this.r = r;
            this.p = p;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            SCryptKeyStretchingParameters that = (SCryptKeyStretchingParameters) o;
            return N == that.N &&
                    r == that.r &&
                    p == that.p;
        }

        @Override
        public int hashCode() {
            return Objects.hash(N, r, p);
        }

        @Override
        public String toString() {
            final StringBuilder sb = new StringBuilder("PBKDF2KeyStretchingParameters{");
            sb.append("N=").append(N);
            sb.append(", r=").append(r);
            sb.append(", p=").append(p);
            sb.append('}');
            return sb.toString();
        }
    }

    private final SCryptKeyStretchingParameters cfg;

    @Override
    public byte[] strengthenKey(byte[] salt, byte[] keyToStrengthen, int desiredKeyLengthInBit) {
        if (desiredKeyLengthInBit % 8 != 0)
            throw new IllegalArgumentException("desiredKeyLengthInBit must be a multiple of 8");

        final byte[] key = SCrypt.generate(keyToStrengthen, salt, cfg.getN(), cfg.getR(), cfg.getP(), desiredKeyLengthInBit);
        return key;
    }
}

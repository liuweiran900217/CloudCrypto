package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/9/20.
 *
 * Key Decapsulation parameters for Rouselakis-Waters CP-ABE.
 */
public class CPABERW13DecapsulationParameters implements CipherParameters {
    private CPABERW13PublicKeyParameters publicKeyParameters;
    private CPABERW13SecretKeyParameters secretKeyParameters;
    private int[][] accessPolicy;
    private String[] rhos;
    private CPABERW13CiphertextParameters ciphertextParameters;

    public CPABERW13DecapsulationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            int[][] accessPolicy,
            String[] rhos,
            CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (CPABERW13PublicKeyParameters)publicKeyParameters;
        this.secretKeyParameters = (CPABERW13SecretKeyParameters)secretKeyParameters;
        this.accessPolicy = accessPolicy;
        this.rhos = Arrays.copyOf(rhos, rhos.length);
        this.ciphertextParameters = (CPABERW13CiphertextParameters)ciphertextParameters;
    }

    public CPABERW13PublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public CPABERW13SecretKeyParameters getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public CPABERW13CiphertextParameters getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public int getLength() { return this.rhos.length; }

    public String[] getRhos() { return Arrays.copyOf(rhos, rhos.length); }

    public String getRhoAt(int index) { return this.rhos[index]; }

    public int[][] getAccessPolicy() { return this.accessPolicy; }
}
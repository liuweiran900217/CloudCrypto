package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/9/20.
 *
 * Key Decapsulation parameters for Rouselakis-Waters CP-ABE.
 */
public class CPABERW13DecapsulationParameters implements CipherParameters {
    private CPABERW13PublicKeySerParameter publicKeyParameters;
    private CPABERW13SecretKeySerParameter secretKeyParameters;
    private int[][] accessPolicy;
    private String[] rhos;
    private CPABERW13CipherSerParameter ciphertextParameters;

    public CPABERW13DecapsulationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            int[][] accessPolicy,
            String[] rhos,
            CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (CPABERW13PublicKeySerParameter)publicKeyParameters;
        this.secretKeyParameters = (CPABERW13SecretKeySerParameter)secretKeyParameters;
        this.accessPolicy = accessPolicy;
        this.rhos = rhos;
        this.ciphertextParameters = (CPABERW13CipherSerParameter)ciphertextParameters;
    }

    public CPABERW13PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public CPABERW13SecretKeySerParameter getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public CPABERW13CipherSerParameter getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public int getLength() { return this.rhos.length; }

    public String[] getRhos() { return this.rhos; }

    public String getRhoAt(int index) { return this.rhos[index]; }

    public int[][] getAccessPolicy() { return this.accessPolicy; }
}
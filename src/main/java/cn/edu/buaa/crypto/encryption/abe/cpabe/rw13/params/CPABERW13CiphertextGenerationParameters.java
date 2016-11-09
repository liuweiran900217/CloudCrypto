package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/9/20.
 *
 * Ciphertext Generation parameters for Rouselakis-Waters CP-ABE.
 */
public class CPABERW13CiphertextGenerationParameters implements CipherParameters {
    private CPABERW13PublicKeySerParameter publicKeyParameters;
    private int[][] accessPolicy;
    private String[] rhos;

    public CPABERW13CiphertextGenerationParameters(
            CipherParameters publicKeyParameters, int[][] accessPolicy, String[] rhos) {
        this.publicKeyParameters = (CPABERW13PublicKeySerParameter) publicKeyParameters;
        this.accessPolicy = accessPolicy;
        this.rhos = rhos;
    }

    public CPABERW13PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getRhos() {
        return this.rhos;
    }

    public String getRhoAt(int index) { return rhos[index]; }

    public int[][] getAccessPolicy() { return this. accessPolicy; }

    public int getLength() { return this.rhos.length; }

}

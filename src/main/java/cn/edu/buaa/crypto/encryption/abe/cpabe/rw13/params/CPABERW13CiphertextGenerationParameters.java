package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.encryption.abe.cpabe.CPABEEngine;
import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/9/20.
 *
 * Ciphertext Generation parameters for Rouselakis-Waters CP-ABE.
 */
public class CPABERW13CiphertextGenerationParameters implements CipherParameters {
    private CPABERW13PublicKeyParameters publicKeyParameters;
    private int[][] accessPolicy;
    private String[] rhos;

    public CPABERW13CiphertextGenerationParameters(
            CipherParameters publicKeyParameters, int[][] accessPolicy, String[] rhos) {
        this.publicKeyParameters = (CPABERW13PublicKeyParameters) publicKeyParameters;
        this.accessPolicy = accessPolicy;
        this.rhos = Arrays.copyOf(rhos, rhos.length);
    }

    public CPABERW13PublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getRhos() {
        return Arrays.copyOf(this.rhos, this.rhos.length);
    }

    public String getRhoAt(int index) { return rhos[index]; }

    public int[][] getAccessPolicy() { return this. accessPolicy; }

    public int getLength() { return this.rhos.length; }

}

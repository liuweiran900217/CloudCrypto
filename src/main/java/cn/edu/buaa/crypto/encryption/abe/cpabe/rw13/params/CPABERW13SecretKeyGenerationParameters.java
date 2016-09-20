package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/9/20.
 *
 * Secret Key Generation parameters for Rouselakis-Waters CP-ABE.
 */
public class CPABERW13SecretKeyGenerationParameters extends KeyGenerationParameters {
    private CPABERW13MasterSecretKeyParameters masterSecretKeyParameters;
    private CPABERW13PublicKeyParameters publicKeyParameters;
    private String[] attributes;

    public CPABERW13SecretKeyGenerationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters,
            String[] attributes) {
        super(null, PairingUtils.STENGTH);
        this.masterSecretKeyParameters = (CPABERW13MasterSecretKeyParameters)masterSecretKeyParameters;
        this.publicKeyParameters = (CPABERW13PublicKeyParameters)publicKeyParameters;
        this.attributes = Arrays.copyOf(attributes, attributes.length);
    }

    public CPABERW13MasterSecretKeyParameters getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public CPABERW13PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getAttributeAt(int index) {
        return this.attributes[index];
    }

    public String[] getAttributes() {
        return Arrays.copyOf(attributes, attributes.length);
    }

    public int getLength() {
        return this.attributes.length;
    }
}
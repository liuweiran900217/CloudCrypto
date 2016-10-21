package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params;

import cn.edu.buaa.crypto.algebra.params.PairingParametersGenerationParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

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
        super(null, PairingParametersGenerationParameters.STENGTH);
        this.masterSecretKeyParameters = (CPABERW13MasterSecretKeyParameters)masterSecretKeyParameters;
        this.publicKeyParameters = (CPABERW13PublicKeyParameters)publicKeyParameters;
        this.attributes = new String[attributes.length];
        System.arraycopy(attributes, 0, this.attributes, 0, this.attributes.length);
    }

    public CPABERW13MasterSecretKeyParameters getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public CPABERW13PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getAttributeAt(int index) {
        return this.attributes[index];
    }

    public String[] getAttributes() {
        return this.attributes;
    }

    public int getLength() {
        return this.attributes.length;
    }
}
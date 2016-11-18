package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.genparams;

import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aPublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE ciphertext generation parameter.
 */
public class KPABEGPSW06aCiphertextGenerationParameter implements CipherParameters {
    private KPABEGPSW06aPublicKeySerParameter publicKeyParameters;
    private String[] attributes;

    public KPABEGPSW06aCiphertextGenerationParameter(CipherParameters publicKeyParameters, String[] attributes) {
        this.publicKeyParameters = (KPABEGPSW06aPublicKeySerParameter)publicKeyParameters;
        assert(attributes.length <= this.publicKeyParameters.getMaxAttributesNum());
        this.attributes = attributes;
    }

    public KPABEGPSW06aPublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getAttributes() { return this.attributes; }
}

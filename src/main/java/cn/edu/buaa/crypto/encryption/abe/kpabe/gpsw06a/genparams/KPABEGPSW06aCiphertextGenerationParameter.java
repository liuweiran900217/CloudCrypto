package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.genparams;

import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aPublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
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
        this.attributes = PairingUtils.removeDuplicates(attributes);
        assert(attributes.length <= this.publicKeyParameters.getMaxAttributesNum());
    }

    public KPABEGPSW06aPublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getAttributes() { return this.attributes; }
}

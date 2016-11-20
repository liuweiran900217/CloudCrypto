package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.genparams;

import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aPublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE ciphertext generation parameter.
 */
public class KPABEGPSW06aEncryptionGenerationParameter implements CipherParameters {
    private KPABEGPSW06aPublicKeySerParameter publicKeyParameters;
    private String[] attributes;
    private Element message;

    public KPABEGPSW06aEncryptionGenerationParameter(CipherParameters publicKeyParameters, String[] attributes, Element message) {
        this.publicKeyParameters = (KPABEGPSW06aPublicKeySerParameter)publicKeyParameters;
        this.attributes = PairingUtils.removeDuplicates(attributes);
        assert(attributes.length <= this.publicKeyParameters.getMaxAttributesNum());
        this.message = message.getImmutable();
    }

    public KPABEGPSW06aPublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getAttributes() { return this.attributes; }

    public Element getMessage() { return this.message.duplicate(); }
}

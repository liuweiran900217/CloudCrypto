package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.genparams;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aCipherSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aSecretKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE decryption generation parameter.
 */
public class KPABEGPSW06aDecryptionGenerationParameter implements CipherParameters {
    private KPABEGPSW06aPublicKeySerParameter publicKeyParameters;
    private KPABEGPSW06aSecretKeySerParameter secretKeyParameters;
    private String[] attributes;
    private KPABEGPSW06aCipherSerParameter ciphertextParameters;
    private AccessControlEngine accessControlEngine;

    public KPABEGPSW06aDecryptionGenerationParameter(
            AccessControlEngine accessControlEngine, CipherParameters publicKeyParameters, CipherParameters secretKeyParameters,
            String[] attributes, CipherParameters ciphertextParameters) {
        this.accessControlEngine = accessControlEngine;
        this.publicKeyParameters = (KPABEGPSW06aPublicKeySerParameter)publicKeyParameters;
        this.secretKeyParameters = (KPABEGPSW06aSecretKeySerParameter)secretKeyParameters;
        assert(attributes.length <= this.publicKeyParameters.getMaxAttributesNum());
        this.attributes = attributes;
        this.ciphertextParameters = (KPABEGPSW06aCipherSerParameter)ciphertextParameters;
    }

    public KPABEGPSW06aPublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public KPABEGPSW06aSecretKeySerParameter getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public KPABEGPSW06aCipherSerParameter getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public String[] getAttributes() { return this.attributes; }

    public AccessControlEngine getAccessControlEngine() { return this.accessControlEngine; }
}

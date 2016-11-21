package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.genparams;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aPublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE decryption generation parameter.
 */
public class KPABEGPSW06aDecryptionGenerationParameter extends PairingDecryptionGenerationParameter {
    private String[] attributes;
    private AccessControlEngine accessControlEngine;

    public KPABEGPSW06aDecryptionGenerationParameter(
            AccessControlEngine accessControlEngine, PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter,
            String[] attributes, PairingCipherSerParameter ciphertextParameter) {
        super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
        assert(attributes.length <= ((KPABEGPSW06aPublicKeySerParameter)publicKeyParameter).getMaxAttributesNum());
        this.accessControlEngine = accessControlEngine;
        this.attributes = PairingUtils.removeDuplicates(attributes);
    }

    public String[] getAttributes() { return this.attributes; }

    public AccessControlEngine getAccessControlEngine() { return this.accessControlEngine; }
}

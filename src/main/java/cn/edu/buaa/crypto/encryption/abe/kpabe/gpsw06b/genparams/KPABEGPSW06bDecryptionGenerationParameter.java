package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.genparams;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Goyal-Pandey-Sahai-Waters large-universe KP-ABE with random oracles decryption generation parameter.
 */
public class KPABEGPSW06bDecryptionGenerationParameter extends PairingDecryptionGenerationParameter {
    private String[] attributes;
    private AccessControlEngine accessControlEngine;

    public KPABEGPSW06bDecryptionGenerationParameter(
            AccessControlEngine accessControlEngine, PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter,
            String[] attributes, PairingCipherSerParameter ciphertextParameter) {
        super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
        this.accessControlEngine = accessControlEngine;
        this.attributes = PairingUtils.removeDuplicates(attributes);
    }

    public String[] getAttributes() { return this.attributes; }

    public AccessControlEngine getAccessControlEngine() { return this.accessControlEngine; }
}

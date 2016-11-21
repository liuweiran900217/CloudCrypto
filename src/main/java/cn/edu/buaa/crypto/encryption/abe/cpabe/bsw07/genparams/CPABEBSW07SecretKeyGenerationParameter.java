package cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;


/**
 * Created by Weiran Liu on 2016/11/19.
 *
 * Bethencourt-Sahai-Waters large-universe CP-ABE secret key generation parameter.
 */
public class CPABEBSW07SecretKeyGenerationParameter extends PairingKeyGenerationParameter {
    private String[] attributes;

    public CPABEBSW07SecretKeyGenerationParameter(
            PairingKeySerParameter publicKeyParameter, PairingKeySerParameter masterSecretKeyParameter, String[] attributes) {
        super(publicKeyParameter, masterSecretKeyParameter);
        this.attributes = PairingUtils.removeDuplicates(attributes);
    }

    public String[] getAttributes() { return this.attributes; }
}
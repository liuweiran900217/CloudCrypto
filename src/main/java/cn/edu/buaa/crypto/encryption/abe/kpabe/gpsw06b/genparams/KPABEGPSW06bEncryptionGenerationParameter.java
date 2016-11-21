package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingEncryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Goyal-Pandey-Sahai-Waters large-universe KP-ABE with random oracles encryption generation parameter.
 */
public class KPABEGPSW06bEncryptionGenerationParameter extends PairingEncryptionGenerationParameter {
    private String[] attributes;

    public KPABEGPSW06bEncryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, String[] attributes, Element message) {
        super(publicKeyParameter, message);
        this.attributes = PairingUtils.removeDuplicates(attributes);
    }

    public String[] getAttributes() {
        return this.attributes;
    }
}

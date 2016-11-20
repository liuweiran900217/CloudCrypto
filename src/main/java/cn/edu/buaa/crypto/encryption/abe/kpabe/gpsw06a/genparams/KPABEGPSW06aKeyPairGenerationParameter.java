package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE public key / master secret key pair generation parameter.
 */
public class KPABEGPSW06aKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    private int maxAttributesNum;

    public KPABEGPSW06aKeyPairGenerationParameter(PairingParameters pairingParameters, int maxAttributesNum) {
        super(pairingParameters);

        this.maxAttributesNum = maxAttributesNum;
    }

    public int getMaxAttributesNum() { return this.maxAttributesNum; }
}
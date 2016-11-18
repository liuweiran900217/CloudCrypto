package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE public key / master secret key pair generation parameter.
 */
public class KPABEGPSW06aKeyPairGenerationParameter extends KeyGenerationParameters {
    private int maxAttributesNum;
    private PairingParameters pairingParameters;

    public KPABEGPSW06aKeyPairGenerationParameter(PairingParameters pairingParameters, int maxAttributesNum) {
        super(null, PairingParametersGenerationParameter.STENGTH);

        this.maxAttributesNum = maxAttributesNum;
        this.pairingParameters = pairingParameters;
    }

    public PairingParameters getPairingParameters() { return this.pairingParameters; }

    public int getMaxAttributesNum() { return this.maxAttributesNum; }
}
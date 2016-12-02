package cn.edu.buaa.crypto.encryption.be.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/12/2.
 *
 * BE public key / master secret key pair generation parameter.
 */
public class BEKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    private int maxUserNum;

    public BEKeyPairGenerationParameter(PairingParameters pairingParameters, int maxUserNum) {
        super(pairingParameters);
        this.maxUserNum = maxUserNum;
    }

    public int getMaxUserNum() { return this.maxUserNum; }
}
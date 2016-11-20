package cn.edu.buaa.crypto.encryption.hibbe.llw14.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu composite-order HIBBE public key / master secret key generation parameter.
 */
public class HIBBELLW14KeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    private int maxUser;

    public HIBBELLW14KeyPairGenerationParameter(PairingParameters pairingParameters, int maxUser) {
        super(pairingParameters);
        this.maxUser = maxUser;
    }

    public int getMaxUser() { return this.maxUser; }
}

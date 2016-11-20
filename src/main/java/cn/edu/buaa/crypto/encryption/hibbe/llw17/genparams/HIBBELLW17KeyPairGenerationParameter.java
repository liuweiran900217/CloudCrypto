package cn.edu.buaa.crypto.encryption.hibbe.llw17.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE public key / master secret key pair generation parameter.
 */
public class HIBBELLW17KeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    private int maxUser;

    public HIBBELLW17KeyPairGenerationParameter(PairingParameters pairingParameters, int maxUser) {
        super(pairingParameters);
        this.maxUser = maxUser;
    }

    public int getMaxUser() { return this.maxUser; }
}

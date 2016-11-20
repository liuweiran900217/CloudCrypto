package cn.edu.buaa.crypto.encryption.hibbe.llw16a.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE public Key / master secret key generation parameters.
 */
public class HIBBELLW16aKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    private int maxUser;

    public HIBBELLW16aKeyPairGenerationParameter(PairingParameters pairingParameters, int maxUser) {
        super(pairingParameters);

        this.maxUser = maxUser;
    }

    public int getMaxUser() { return this.maxUser; }
}

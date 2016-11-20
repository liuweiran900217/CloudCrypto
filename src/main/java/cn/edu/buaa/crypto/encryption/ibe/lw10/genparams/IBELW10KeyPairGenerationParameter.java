package cn.edu.buaa.crypto.encryption.ibe.lw10.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 16/5/6.
 *
 * Lewko-Waters IBE public key / master secret key pair generation parameter.
 */

public class IBELW10KeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    public IBELW10KeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(pairingParameters);
    }
}

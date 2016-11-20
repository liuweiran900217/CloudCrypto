package cn.edu.buaa.crypto.signature.pks.bb08;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Boneh-Boyen 2008 signature key pair generation parameter.
 */
public class BB08SignKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    public BB08SignKeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(pairingParameters);
    }
}
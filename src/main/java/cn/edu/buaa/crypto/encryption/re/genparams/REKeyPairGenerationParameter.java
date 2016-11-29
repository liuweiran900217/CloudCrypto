package cn.edu.buaa.crypto.encryption.re.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Revocation encryption public key / master secret key pair generation parameter.
 */
public class REKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {

    public REKeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(pairingParameters);
    }
}

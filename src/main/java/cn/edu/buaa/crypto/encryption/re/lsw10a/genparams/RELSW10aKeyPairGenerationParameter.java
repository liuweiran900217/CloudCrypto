package cn.edu.buaa.crypto.encryption.re.lsw10a.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Sahai-Waters revocation encryption public key / master secret key pair generation parameter.
 */
public class RELSW10aKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {

    public RELSW10aKeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(pairingParameters);
    }
}

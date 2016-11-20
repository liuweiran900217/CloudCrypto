package cn.edu.buaa.crypto.signature.pks.bls01;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/10/21.
 *
 * Boneh-Lynn-Shacham signature public key / secret key pair generation parameters.
 */
public class BLS01SignKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {

    public BLS01SignKeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(pairingParameters);
    }
}

package cn.edu.buaa.crypto.signature.pks.bb04;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/10/21.
 *
 * Boneh-Boyen short signatures public key / secret key generation parameters.
 */
public class BB04SignKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    public BB04SignKeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(pairingParameters);
    }
}
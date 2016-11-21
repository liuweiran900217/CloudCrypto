package cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/11/19.
 *
 * Bethencourt-Sahai-Waters large-universe CP-ABE public key / master secret key pair generation parameter.
 */
public class CPABEBSW07KeyPairGenerationParameter extends PairingKeyPairGenerationParameter {

    public CPABEBSW07KeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(pairingParameters);
    }
}
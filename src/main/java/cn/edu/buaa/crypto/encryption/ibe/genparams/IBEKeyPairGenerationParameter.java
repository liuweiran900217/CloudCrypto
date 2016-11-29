package cn.edu.buaa.crypto.encryption.ibe.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Identity-Based Encryption public key / master secret key pair generation parameter.
 */
public class IBEKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    public IBEKeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(pairingParameters);
    }
}
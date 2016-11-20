package cn.edu.buaa.crypto.encryption.hibe.bbg05.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Public Key / Master Secret Key generation parameters for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05KeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    private int maxDepth;

    public HIBEBBG05KeyPairGenerationParameter(PairingParameters pairingParameters, int maxDepth) {
        super(pairingParameters);

        this.maxDepth = maxDepth;
    }

    public int getMaxDepth() { return this.maxDepth; }
}

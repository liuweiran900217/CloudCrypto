package cn.edu.buaa.crypto.encryption.hibe.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 15-9-30.
 *
 * HIBE public key / master secret key generation parameter.
 */
public class HIBEKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    private int maxDepth;

    public HIBEKeyPairGenerationParameter(PairingParameters pairingParameters, int maxDepth) {
        super(pairingParameters);

        this.maxDepth = maxDepth;
    }

    public int getMaxDepth() { return this.maxDepth; }

}

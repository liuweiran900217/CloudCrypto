package cn.edu.buaa.crypto.encryption.hibe.bb04.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 15-9-30.
 *
 * Public key / master secret key parameters for Boneh-Boyen HIBE scheme.
 */
public class HIBEBB04KeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    private int maxDepth;

    public HIBEBB04KeyPairGenerationParameter(PairingParameters pairingParameters, int maxDepth) {
        super(pairingParameters);

        this.maxDepth = maxDepth;
    }

    public int getMaxDepth() { return this.maxDepth; }

}

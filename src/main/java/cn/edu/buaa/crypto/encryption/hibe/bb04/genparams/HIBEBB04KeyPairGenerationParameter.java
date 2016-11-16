package cn.edu.buaa.crypto.encryption.hibe.bb04.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 15-9-30.
 *
 * Public key / master secret key parameters for Boneh-Boyen HIBE scheme.
 */
public class HIBEBB04KeyPairGenerationParameter extends KeyGenerationParameters {
    private int maxDepth;
    private PairingParameters pairingParameters;

    public HIBEBB04KeyPairGenerationParameter(PairingParameters pairingParameters, int maxDepth) {
        super(null, PairingParametersGenerationParameter.STENGTH);

        this.maxDepth = maxDepth;
        this.pairingParameters = pairingParameters;
    }

    public PairingParameters getPairingParameters() { return this.pairingParameters; }

    public int getMaxDepth() { return this.maxDepth; }

}

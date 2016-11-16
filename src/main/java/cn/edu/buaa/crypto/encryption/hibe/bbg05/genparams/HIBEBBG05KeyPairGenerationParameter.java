package cn.edu.buaa.crypto.encryption.hibe.bbg05.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Public Key / Master Secret Key generation parameters for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05KeyPairGenerationParameter extends KeyGenerationParameters {
    private int maxDepth;
    private PairingParameters pairingParameters;

    public HIBEBBG05KeyPairGenerationParameter(PairingParameters pairingParameters, int maxDepth) {
        super(null, PairingParametersGenerationParameter.STENGTH);

        this.maxDepth = maxDepth;
        this.pairingParameters = pairingParameters;
    }

    public PairingParameters getPairingParameters() { return this.pairingParameters; }

    public int getMaxDepth() { return this.maxDepth; }
}

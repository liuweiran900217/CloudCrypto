package cn.edu.buaa.crypto.encryption.ibe.lw10.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameters;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/5/6.
 * Modified by Weiran Liu on 16/5/16.
 */

public class IBELW10KeyPairGenerationParameter extends KeyGenerationParameters {
    private PairingParameters pairingParameters;

    public IBELW10KeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(null, PairingParametersGenerationParameters.STENGTH);
        this.pairingParameters = pairingParameters;
    }

    public PairingParameters getPairingParameters() { return this.pairingParameters; }
}

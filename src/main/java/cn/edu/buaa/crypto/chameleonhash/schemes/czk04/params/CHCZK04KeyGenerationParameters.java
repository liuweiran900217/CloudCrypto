package cn.edu.buaa.crypto.chameleonhash.schemes.czk04.params;

import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 */
public class CHCZK04KeyGenerationParameters extends KeyGenerationParameters {
    private PairingParameters pairingParameters;

    public CHCZK04KeyGenerationParameters(PairingParameters pairingParameters) {
        super(null, CHEngine.STRENGTH);
        this.pairingParameters = pairingParameters;
    }

    public PairingParameters getParameters()
    {
        return this.pairingParameters;
    }
}

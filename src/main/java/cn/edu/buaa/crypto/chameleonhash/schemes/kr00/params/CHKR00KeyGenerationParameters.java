package cn.edu.buaa.crypto.chameleonhash.schemes.kr00.params;

import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/5.
 */
public class CHKR00KeyGenerationParameters extends KeyGenerationParameters {
    private PairingParameters pairingParameters;

    public CHKR00KeyGenerationParameters(PairingParameters pairingParameters) {
        super(null, CHEngine.STRENGTH);
        this.pairingParameters = pairingParameters;
    }

    public PairingParameters getParameters()
    {
        return this.pairingParameters;
    }
}

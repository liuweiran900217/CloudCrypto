package cn.edu.buaa.crypto.chameleonhash.schemes.czk04.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Chameleon Hash Key / Trapdoor generation parameters for Chen-Zhang-Kim Chameleon hash.
 */
public class CHCZK04KeyGenerationParameters extends KeyGenerationParameters {
    private PairingParameters pairingParameters;

    public CHCZK04KeyGenerationParameters(PairingParameters pairingParameters) {
        super(null, PairingUtils.STENGTH);
        this.pairingParameters = pairingParameters;
    }

    public PairingParameters getParameters()
    {
        return this.pairingParameters;
    }
}

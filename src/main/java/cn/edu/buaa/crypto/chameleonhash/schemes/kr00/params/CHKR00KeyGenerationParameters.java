package cn.edu.buaa.crypto.chameleonhash.schemes.kr00.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/5.
 *
 * Chameleon Hash Key / Trapdoor generation parameters for Katz-Rabin Chameleon hash.
 */
public class CHKR00KeyGenerationParameters extends KeyGenerationParameters {
    private PairingParameters pairingParameters;

    public CHKR00KeyGenerationParameters(PairingParameters pairingParameters) {
        super(null, PairingUtils.STENGTH);
        this.pairingParameters = pairingParameters;
    }

    public PairingParameters getParameters()
    {
        return this.pairingParameters;
    }
}

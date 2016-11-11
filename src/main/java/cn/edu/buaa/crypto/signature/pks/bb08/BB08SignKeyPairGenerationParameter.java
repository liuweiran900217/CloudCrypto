package cn.edu.buaa.crypto.signature.pks.bb08;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Boneh-Boyen 2008 signature key pair generation parameter.
 */
public class BB08SignKeyPairGenerationParameter extends KeyGenerationParameters {
    private PairingParameters pairingParameters;

    public BB08SignKeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.pairingParameters = pairingParameters;
    }

    public PairingParameters getPairingParameters()
    {
        return this.pairingParameters;
    }
}
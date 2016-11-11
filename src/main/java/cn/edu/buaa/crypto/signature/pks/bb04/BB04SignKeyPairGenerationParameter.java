package cn.edu.buaa.crypto.signature.pks.bb04;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/10/21.
 *
 * Boneh-Boyen short signatures public key / secret key generation parameters.
 */
public class BB04SignKeyPairGenerationParameter extends KeyGenerationParameters {
    private PairingParameters pairingParameters;

    public BB04SignKeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.pairingParameters = pairingParameters;
    }

    public PairingParameters getPairingParameters()
    {
        return this.pairingParameters;
    }
}
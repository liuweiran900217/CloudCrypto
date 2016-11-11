package cn.edu.buaa.crypto.signature.pks.bls01;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/10/21.
 *
 * Boneh-Lynn-Shacham signature public key / secret key pair generation parameters.
 */
public class BLS01SignKeyPairGenerationParameter extends KeyGenerationParameters {
    private PairingParameters pairingParameters;

    public BLS01SignKeyPairGenerationParameter(PairingParameters pairingParameters)
    {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.pairingParameters = pairingParameters;
    }

    public PairingParameters getPairingParameters()
    {
        return this.pairingParameters;
    }
}

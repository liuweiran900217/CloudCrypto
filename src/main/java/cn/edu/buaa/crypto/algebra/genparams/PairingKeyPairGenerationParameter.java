package cn.edu.buaa.crypto.algebra.genparams;

import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/11/20.
 *
 * Pairing public key / master secret key generation parameter.
 */
public class PairingKeyPairGenerationParameter extends KeyGenerationParameters {
    private PairingParameters pairingParameters;

    public PairingKeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.pairingParameters = pairingParameters;
    }

    public PairingParameters getPairingParameters() { return this.pairingParameters; }
}
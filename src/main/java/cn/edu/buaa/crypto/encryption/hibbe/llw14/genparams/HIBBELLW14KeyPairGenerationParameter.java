package cn.edu.buaa.crypto.encryption.hibbe.llw14.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu composite-order HIBBE public key / master secret key generation parameter.
 */
public class HIBBELLW14KeyPairGenerationParameter extends KeyGenerationParameters {
    private int maxUser;
    private PairingParameters pairingParameters;

    public HIBBELLW14KeyPairGenerationParameter(PairingParameters pairingParameters, int maxUser) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.pairingParameters = pairingParameters;
        this.maxUser = maxUser;
    }

    public PairingParameters getPairingParameters() { return this.pairingParameters; }

    public int getMaxUser() { return this.maxUser; }
}

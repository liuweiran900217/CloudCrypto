package cn.edu.buaa.crypto.encryption.hibbe.llw17.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE public key / master secret key pair generation parameter.
 */
public class HIBBELLW17KeyPairGenerationParameter extends KeyGenerationParameters {
    private int maxUser;
    private PairingParameters pairingParameters;

    public HIBBELLW17KeyPairGenerationParameter(PairingParameters pairingParameters, int maxUser) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.pairingParameters = pairingParameters;
        this.maxUser = maxUser;
    }

    public PairingParameters getPairingParameters() { return this.pairingParameters; }

    public int getMaxUser() { return this.maxUser; }
}

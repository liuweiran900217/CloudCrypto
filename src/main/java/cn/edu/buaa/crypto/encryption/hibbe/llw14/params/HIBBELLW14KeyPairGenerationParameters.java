package cn.edu.buaa.crypto.encryption.hibbe.llw14.params;

import cn.edu.buaa.crypto.algebra.params.PairingParametersGenerationParameters;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Public Key / Master Secret Key generation parameters for Liu-Liu-Wu HIBBE published in 2016.
 */
public class HIBBELLW14KeyPairGenerationParameters extends KeyGenerationParameters {
    private int maxUser;
    private PairingParameters pairingParameters;

    public HIBBELLW14KeyPairGenerationParameters(PairingParameters pairingParameters, int maxUser) {
        super(null, PairingParametersGenerationParameters.STENGTH);
        this.pairingParameters = pairingParameters;
        this.maxUser = maxUser;
    }

    public PairingParameters getPairingParameters() { return this.pairingParameters; }

    public int getMaxUser() { return this.maxUser; }
}

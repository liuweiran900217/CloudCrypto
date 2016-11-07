package cn.edu.buaa.crypto.encryption.hibbe.llw16a.params;

import cn.edu.buaa.crypto.algebra.params.PairingParametersGenerationParameters;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE public Key / master secret key generation parameters.
 */
public class HIBBELLW16aKeyPairGenerationParameters extends KeyGenerationParameters {
    private int maxUser;
    private PairingParameters pairingParameters;

    public HIBBELLW16aKeyPairGenerationParameters(PairingParameters pairingParameters, int maxUser) {
        super(null, PairingParametersGenerationParameters.STENGTH);

        this.pairingParameters = pairingParameters;
        this.maxUser = maxUser;
    }

    public PairingParameters getPairingParameters() { return this.pairingParameters; }

    public int getMaxUser() { return this.maxUser; }
}

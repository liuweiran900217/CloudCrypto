package cn.edu.buaa.crypto.application.llw15.params;

import cn.edu.buaa.crypto.algebra.params.PairingParametersGenerationParameters;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/5/18.
 *
 * Public Key / Master Secret Key generation parameters for Liu-Liu-Wu EHR role-based access control.
 */
public class RBACLLW15KeyPairGenerationParameters extends KeyGenerationParameters {
    private int maxRoleNumber;
    private PairingParameters pairingParameters;

    public RBACLLW15KeyPairGenerationParameters(PairingParameters pairingParameters, int maxRoleNumber) {
        super(null, PairingParametersGenerationParameters.STENGTH);

        this.pairingParameters = pairingParameters;
        this.maxRoleNumber = maxRoleNumber;
    }

    public PairingParameters getPairingParameters() { return this.pairingParameters; }

    public int getMaxRoleNumber() { return this.maxRoleNumber; }
}


package cn.edu.buaa.crypto.application.llw15.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 16/5/18.
 *
 * Public Key / Master Secret Key generation parameters for Liu-Liu-Wu EHR role-based access control.
 */
public class RBACLLW15KeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    private int maxRoleNumber;

    public RBACLLW15KeyPairGenerationParameter(PairingParameters pairingParameters, int maxRoleNumber) {
        super(pairingParameters);
        this.maxRoleNumber = maxRoleNumber;
    }

    public int getMaxRoleNumber() { return this.maxRoleNumber; }
}


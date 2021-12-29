package cn.edu.buaa.crypto.encryption.abe.cpabe.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyDelegationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;

public class CPABEReKeyGenerationParameter extends PairingKeyDelegationParameter {
    private String ID;

    public CPABEReKeyGenerationParameter(
            PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter, String ID) {
        super(publicKeyParameter, secretKeyParameter);
        this.ID = ID;
    }

    public String getID() { return this.ID; }
}

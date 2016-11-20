package cn.edu.buaa.crypto.encryption.hibbe.llw16b.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.Signer;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE key pair generation parameter.
 */
public class HIBBELLW16bKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    private int maxUser;
    private Signer signer;

    public HIBBELLW16bKeyPairGenerationParameter(PairingParameters pairingParameters, Signer signer, int maxUser) {
        super(pairingParameters);

        this.maxUser = maxUser;
        this.signer = signer;
    }

    public int getMaxUser() { return this.maxUser; }

    public Signer getSigner() { return this.signer; }
}


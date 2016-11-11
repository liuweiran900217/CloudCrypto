package cn.edu.buaa.crypto.encryption.hibbe.llw16b.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.Signer;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE key pair generation parameter.
 */
public class HIBBELLW16bKeyPairGenerationParameter  extends KeyGenerationParameters {
    private int maxUser;
    private PairingParameters pairingParameters;
    private Signer signer;

    public HIBBELLW16bKeyPairGenerationParameter(PairingParameters pairingParameters, Signer signer, int maxUser) {
        super(null, PairingParametersGenerationParameter.STENGTH);

        this.pairingParameters = pairingParameters;
        this.maxUser = maxUser;
        this.signer = signer;
    }

    public PairingParameters getPairingParameters() { return this.pairingParameters; }

    public int getMaxUser() { return this.maxUser; }

    public Signer getSigner() { return this.signer; }
}


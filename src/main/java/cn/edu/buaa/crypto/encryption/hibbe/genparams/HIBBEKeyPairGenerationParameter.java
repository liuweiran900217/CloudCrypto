package cn.edu.buaa.crypto.encryption.hibbe.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.Signer;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * HIBBE public key / master secret key generation parameter.
 */
public class HIBBEKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    private int maxUser;
    private Signer signer;

    public HIBBEKeyPairGenerationParameter(PairingParameters pairingParameters, int maxUser) {
        super(pairingParameters);
        this.maxUser = maxUser;
        this.signer = null;
    }

    public HIBBEKeyPairGenerationParameter(PairingParameters pairingParameters, int maxUser, Signer signer) {
        super(pairingParameters);
        this.maxUser = maxUser;
        this.signer = signer;
    }

    public Signer getSigner() { return this.signer; }

    public int getMaxUser() { return this.maxUser; }
}

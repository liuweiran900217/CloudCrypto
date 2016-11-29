package cn.edu.buaa.crypto.encryption.hibbe.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * HIBBE decryption generation parameter.
 */
public class HIBBEDecryptionGenerationParameter extends PairingDecryptionGenerationParameter {
    private String[] ids;
    private Signer signer;
    private Digest digest;

    public HIBBEDecryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter,
                                              String[] ids, PairingCipherSerParameter ciphertextParameter) {
        super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
        this.ids = ids;
    }

    public void setSigner(Signer signer) {
        this.signer = signer;
    }

    public Signer getSigner() {
        return this.signer;
    }

    public void setDigest(Digest digest) { this.digest = digest; }

    public Digest getDigest() { return this.digest; }

    public String[] getIds() { return this.ids; }

    public String getIdsAt(int index) { return this.ids[index]; }
}

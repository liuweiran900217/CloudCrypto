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
        this. signer = null;
        this.digest = null;
    }

    public HIBBEDecryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter,
                                              String[] ids, PairingCipherSerParameter ciphertextParameter, Signer signer) {
        super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
        this.ids = ids;
        this.signer = signer;
        this.digest = null;
    }

    public HIBBEDecryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter,
                                              String[] ids, PairingCipherSerParameter ciphertextParameter, Digest digest) {
        super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
        this.ids = ids;
        this.signer = null;
        this.digest = digest;
    }

    public Signer getSigner() {
        return this.signer;
    }

    public Digest getDigest() { return this.digest; }

    public String[] getIds() { return this.ids; }

    public String getIdsAt(int index) { return this.ids[index]; }
}

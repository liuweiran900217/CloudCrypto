package cn.edu.buaa.crypto.encryption.hibbe.llw17.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17PublicKeySerParameter;
import org.bouncycastle.crypto.Digest;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE decryption generation parameter.
 */
public class HIBBELLW17DecryptionGenerationParameter extends PairingDecryptionGenerationParameter {
    private Digest digest;
    private String[] ids;

    public HIBBELLW17DecryptionGenerationParameter(
            Digest digest, PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter,
            String[] ids, PairingCipherSerParameter ciphertextParameter) {
        super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
        this.digest = digest;
        assert(ids.length == ((HIBBELLW17PublicKeySerParameter)publicKeyParameter).getMaxUser());
        this.ids = ids;
    }

    public Digest getDigest() { return this.digest; }

    public String[] getIds() { return this.ids; }

    public String getIdsAt(int index) { return this.ids[index]; }
}

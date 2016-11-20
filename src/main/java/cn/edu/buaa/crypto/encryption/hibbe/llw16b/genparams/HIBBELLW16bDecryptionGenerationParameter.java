package cn.edu.buaa.crypto.encryption.hibbe.llw16b.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bPublicKeySerParameter;
import org.bouncycastle.crypto.Signer;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE decryption generation parameter.
 */
public class HIBBELLW16bDecryptionGenerationParameter extends PairingDecryptionGenerationParameter {
    private Signer signer;
    private String[] ids;

    public HIBBELLW16bDecryptionGenerationParameter(Signer signer,
            PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter,
            String[] ids, PairingCipherSerParameter ciphertextParameter) {
        super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
        assert(ids.length == ((HIBBELLW16bPublicKeySerParameter)publicKeyParameter).getMaxUser());
        this.signer = signer;
        this.ids = ids;
    }

    public String[] getIds() { return this.ids; }

    public String getIdsAt(int index) { return this.ids[index]; }

    public Signer getSigner() { return this.signer; }
}
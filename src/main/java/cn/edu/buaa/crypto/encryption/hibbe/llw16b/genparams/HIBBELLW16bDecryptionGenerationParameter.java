package cn.edu.buaa.crypto.encryption.hibbe.llw16b.genparams;

import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bSecretKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE decryption generation parameter.
 */
public class HIBBELLW16bDecryptionGenerationParameter implements CipherParameters {
    private Signer signer;
    private HIBBELLW16bPublicKeySerParameter publicKeyParameters;
    private HIBBELLW16bSecretKeySerParameter secretKeyParameters;
    private String[] ids;
    private HIBBELLW16bCipherSerParameter ciphertextParameters;

    public HIBBELLW16bDecryptionGenerationParameter(
            Signer signer,
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            String[] ids,
            CipherParameters ciphertextParameters) {
        this.signer = signer;
        this.publicKeyParameters = (HIBBELLW16bPublicKeySerParameter)publicKeyParameters;
        this.secretKeyParameters = (HIBBELLW16bSecretKeySerParameter)secretKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = new String[ids.length];
        System.arraycopy(ids, 0, this.ids, 0, this.ids.length);
        this.ciphertextParameters = (HIBBELLW16bCipherSerParameter)ciphertextParameters;
    }

    public HIBBELLW16bPublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public HIBBELLW16bSecretKeySerParameter getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public HIBBELLW16bCipherSerParameter getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public String[] getIds() { return this.ids; }

    public String getIdsAt(int index) { return this.ids[index]; }

    public Signer getSigner() { return this.signer; }
}
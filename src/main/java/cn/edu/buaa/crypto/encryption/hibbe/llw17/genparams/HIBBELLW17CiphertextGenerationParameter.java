package cn.edu.buaa.crypto.encryption.hibbe.llw17.genparams;

import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17PublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE ciphertext / session key generation parameter.
 */
public class HIBBELLW17CiphertextGenerationParameter implements CipherParameters {
    private HIBBELLW17PublicKeySerParameter publicKeyParameters;
    private Digest digest;
    private String[] ids;

    public HIBBELLW17CiphertextGenerationParameter(
            Digest digest, CipherParameters publicKeyParameters, String[] ids) {
        this.publicKeyParameters = (HIBBELLW17PublicKeySerParameter)publicKeyParameters;
        this.digest = digest;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = ids;
    }

    public HIBBELLW17PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public Digest getDigest() { return this.digest; }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }
}

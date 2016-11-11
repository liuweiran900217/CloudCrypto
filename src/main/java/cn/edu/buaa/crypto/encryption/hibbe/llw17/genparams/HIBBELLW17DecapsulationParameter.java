package cn.edu.buaa.crypto.encryption.hibbe.llw17.genparams;

import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17CipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17SecretKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE session key decapsulation parameter.
 */
public class HIBBELLW17DecapsulationParameter implements CipherParameters {
    private HIBBELLW17PublicKeySerParameter publicKeyParameters;
    private HIBBELLW17SecretKeySerParameter secretKeyParameters;
    private Digest digest;
    private String[] ids;
    private HIBBELLW17CipherSerParameter ciphertextParameters;

    public HIBBELLW17DecapsulationParameter(
            Digest digest,
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            String[] ids,
            CipherParameters ciphertextParameters) {
        this.digest = digest;
        this.publicKeyParameters = (HIBBELLW17PublicKeySerParameter)publicKeyParameters;
        this.secretKeyParameters = (HIBBELLW17SecretKeySerParameter)secretKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = ids;
        this.ciphertextParameters = (HIBBELLW17CipherSerParameter)ciphertextParameters;
    }

    public HIBBELLW17PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public HIBBELLW17SecretKeySerParameter getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public HIBBELLW17CipherSerParameter getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public Digest getDigest() { return this.digest; }

    public String[] getIds() { return this.ids; }

    public String getIdsAt(int index) { return this.ids[index]; }
}

package cn.edu.buaa.crypto.encryption.hibbe.llw16.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Secret Key Delegation parameters for Liu-Liu-Wu HIBBE published in 2016.
 */
public class HIBBELLW16DelegateGenerationParameters extends KeyGenerationParameters {
    private HIBBELLW16PublicKeyParameters publicKeyParameters;
    private HIBBELLW16SecretKeyParameters secretKeyParameters;
    private int index;
    private String delegateId;

    public HIBBELLW16DelegateGenerationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            int index, String id) {
        super(null, PairingUtils.STENGTH);
        this.publicKeyParameters = (HIBBELLW16PublicKeyParameters)publicKeyParameters;
        this.secretKeyParameters = (HIBBELLW16SecretKeyParameters)secretKeyParameters;
        assert(this.secretKeyParameters.getIdAt(index) == null);
        this.index = index;
        this.delegateId = id;
    }

    public HIBBELLW16PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public HIBBELLW16SecretKeyParameters getSecretKeyParameters() { return this.secretKeyParameters; }

    public int getIndex() { return this.index; }

    public String getDelegateId() { return this.delegateId; }

}
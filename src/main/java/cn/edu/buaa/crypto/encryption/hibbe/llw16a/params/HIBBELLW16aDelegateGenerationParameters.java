package cn.edu.buaa.crypto.encryption.hibbe.llw16a.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE secret key delegation parameters.
 */
public class HIBBELLW16aDelegateGenerationParameters extends KeyGenerationParameters {
    private HIBBELLW16aPublicKeyParameters publicKeyParameters;
    private HIBBELLW16aSecretKeyParameters secretKeyParameters;
    private int index;
    private String delegateId;

    public HIBBELLW16aDelegateGenerationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            int index, String id) {
        super(null, PairingUtils.STENGTH);
        this.publicKeyParameters = (HIBBELLW16aPublicKeyParameters)publicKeyParameters;
        this.secretKeyParameters = (HIBBELLW16aSecretKeyParameters)secretKeyParameters;
        assert(this.secretKeyParameters.getIdAt(index) == null);
        this.index = index;
        this.delegateId = id;
    }

    public HIBBELLW16aPublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public HIBBELLW16aSecretKeyParameters getSecretKeyParameters() { return this.secretKeyParameters; }

    public int getIndex() { return this.index; }

    public String getDelegateId() { return this.delegateId; }

}
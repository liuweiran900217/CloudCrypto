package cn.edu.buaa.crypto.encryption.hibe.bb04.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04SecretKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2015/10/5.
 *
 * Delegation generation parameters for Boneh-Boyen HIBE scheme.
 */
public class HIBEBB04DelegateGenerationParameter extends KeyGenerationParameters {
    private HIBEBB04PublicKeySerParameter publicKeyParameters;
    private HIBEBB04SecretKeySerParameter secretKeyParameters;
    private String delegateId;

    public HIBEBB04DelegateGenerationParameter(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            String id) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.publicKeyParameters = (HIBEBB04PublicKeySerParameter)publicKeyParameters;
        this.secretKeyParameters = (HIBEBB04SecretKeySerParameter)secretKeyParameters;
        this.delegateId = id;
    }

    public HIBEBB04PublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public HIBEBB04SecretKeySerParameter getSecretKeyParameters() { return this.secretKeyParameters; }

    public String getDelegateId() { return this.delegateId; }
}

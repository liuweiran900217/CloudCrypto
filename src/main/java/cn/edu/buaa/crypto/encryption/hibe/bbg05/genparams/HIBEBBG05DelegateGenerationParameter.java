package cn.edu.buaa.crypto.encryption.hibe.bbg05.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05SecretKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Secret Key Delegation generation parameters for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05DelegateGenerationParameter extends KeyGenerationParameters {
    private HIBEBBG05PublicKeySerParameter publicKeyParameters;
    private HIBEBBG05SecretKeySerParameter secretKeyParameters;
    private String delegateId;

    public HIBEBBG05DelegateGenerationParameter(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            String id) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.publicKeyParameters = (HIBEBBG05PublicKeySerParameter)publicKeyParameters;
        this.secretKeyParameters = (HIBEBBG05SecretKeySerParameter)secretKeyParameters;
        this.delegateId = id;
    }

    public HIBEBBG05PublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public HIBEBBG05SecretKeySerParameter getSecretKeyParameters() { return this.secretKeyParameters; }

    public String getDelegateId() { return this.delegateId; }
}

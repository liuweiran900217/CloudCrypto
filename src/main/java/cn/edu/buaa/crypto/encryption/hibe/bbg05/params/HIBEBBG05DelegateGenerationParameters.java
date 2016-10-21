package cn.edu.buaa.crypto.encryption.hibe.bbg05.params;

import cn.edu.buaa.crypto.algebra.params.PairingParametersGenerationParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Secret Key Delegation generation parameters for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05DelegateGenerationParameters extends KeyGenerationParameters {
    private HIBEBBG05PublicKeyParameters publicKeyParameters;
    private HIBEBBG05SecretKeyParameters secretKeyParameters;
    private String delegateId;

    public HIBEBBG05DelegateGenerationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            String id) {
        super(null, PairingParametersGenerationParameters.STENGTH);
        this.publicKeyParameters = (HIBEBBG05PublicKeyParameters)publicKeyParameters;
        this.secretKeyParameters = (HIBEBBG05SecretKeyParameters)secretKeyParameters;
        this.delegateId = id;
    }

    public HIBEBBG05PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public HIBEBBG05SecretKeyParameters getSecretKeyParameters() { return this.secretKeyParameters; }

    public String getDelegateId() { return this.delegateId; }
}

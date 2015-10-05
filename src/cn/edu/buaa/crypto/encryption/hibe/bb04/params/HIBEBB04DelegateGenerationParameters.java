package cn.edu.buaa.crypto.encryption.hibe.bb04.params;

import cn.edu.buaa.crypto.encryption.hibe.bb04.generators.HIBEBB04KeyPairGenerator;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.InvalidParameterException;

/**
 * Created by Weiran Liu on 2015/10/5.
 */
public class HIBEBB04DelegateGenerationParameters  extends KeyGenerationParameters {
    private HIBEBB04PublicKeyParameters publicKeyParameters;
    private HIBEBB04SecretKeyParameters secretKeyParameters;
    private String delegateId;

    public HIBEBB04DelegateGenerationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            String id) {
        super(null, HIBEBB04KeyPairGenerator.STENGTH);
        if (!(publicKeyParameters instanceof HIBEBB04PublicKeyParameters)){
            throw new InvalidParameterException
                    ("Invalid CipherParameter Instance of HIBEBB04 Scheme, find "
                            + publicKeyParameters.getClass().getName() + ", require "
                            + HIBEBB04PublicKeyParameters.class.getName());
        }
        if (!(secretKeyParameters instanceof HIBEBB04SecretKeyParameters)) {
            throw new InvalidParameterException
                    ("Invalid CipherParameter Instance of HIBEBB04 Scheme, find "
                            + secretKeyParameters.getClass().getName() + ", require"
                            + HIBEBB04SecretKeyParameters.class.getName());
        }
        this.publicKeyParameters = (HIBEBB04PublicKeyParameters)publicKeyParameters;
        this.secretKeyParameters = (HIBEBB04SecretKeyParameters)secretKeyParameters;
        this.delegateId = id;
    }

    public HIBEBB04PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }
    public HIBEBB04SecretKeyParameters getSecretKeyParameters() { return this.secretKeyParameters; }
    public String getDelegateId() { return this.delegateId; }
}

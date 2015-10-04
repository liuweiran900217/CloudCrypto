package cn.edu.buaa.crypto.encryption.hibe.bb04.params;

import org.bouncycastle.crypto.CipherParameters;

import java.security.InvalidParameterException;

/**
 * Created by Administrator on 15-10-1.
 */
public class HIBEBB04DecapsulationParameters implements CipherParameters {
    private HIBEBB04PublicKeyParameters publicKeyParameters;
    private HIBEBB04SecretKeyParameters secretKeyParameters;
    private HIBEBB04CiphertextParameters ciphertextParameters;

    public HIBEBB04DecapsulationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            CipherParameters ciphertextParameters) {
        if (!(publicKeyParameters instanceof HIBEBB04PublicKeyParameters)){
            throw new InvalidParameterException
                    ("Invalid CipherParameter Instance of HIBEBB04 Scheme, find "
                            + publicKeyParameters.getClass().getName() + ", require "
                            + HIBEBB04PublicKeyParameters.class.getName());
        }
        if (!(secretKeyParameters instanceof HIBEBB04SecretKeyParameters)){
            throw new InvalidParameterException
                    ("Invalid CipherParameter Instance of HIBEBB04 Scheme, find "
                            + secretKeyParameters.getClass().getName() + ", require "
                            + HIBEBB04SecretKeyParameters.class.getName());
        }
        if (!(ciphertextParameters instanceof HIBEBB04CiphertextParameters)){
            throw new InvalidParameterException
                    ("Invalid CipherParameter Instance of HIBEBB04 Scheme, find "
                            + ciphertextParameters.getClass().getName() + ", require "
                            + HIBEBB04CiphertextParameters.class.getName());
        }
        this.publicKeyParameters = (HIBEBB04PublicKeyParameters)publicKeyParameters;
        this.secretKeyParameters = (HIBEBB04SecretKeyParameters)secretKeyParameters;
        this.ciphertextParameters = (HIBEBB04CiphertextParameters)ciphertextParameters;
    }

    public HIBEBB04PublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public HIBEBB04SecretKeyParameters getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public HIBEBB04CiphertextParameters getCiphertextParameters() {
        return this.ciphertextParameters;
    }
}

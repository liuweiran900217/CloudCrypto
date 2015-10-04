package cn.edu.buaa.crypto.encryption.hibe.bb04.params;

import cn.edu.buaa.crypto.encryption.hibe.bb04.generators.HIBEBB04KeyPairGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.InvalidParameterException;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 15-9-30.
 */
public class HIBEBB04SecretKeyGenerationParameters extends KeyGenerationParameters {

    private HIBEBB04MasterSecretKeyParameters masterSecretKeyParameters;
    private HIBEBB04PublicKeyParameters publicKeyParameters;
    private String[] ids;

    public HIBEBB04SecretKeyGenerationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters,
            String[] ids) {
        super(null, HIBEBB04KeyPairGenerator.STENGTH);

        if (!(publicKeyParameters instanceof HIBEBB04PublicKeyParameters)){
            throw new InvalidParameterException
                    ("Invalid CipherParameter Instance of HIBEBB04 Scheme, find "
                            + publicKeyParameters.getClass().getName() + ", require "
                            + HIBEBB04PublicKeyParameters.class.getName());
        }
        if (!(masterSecretKeyParameters instanceof HIBEBB04MasterSecretKeyParameters)) {
            throw new InvalidParameterException
                    ("Invalid CipherParameter Instance of HIBEBB04 Scheme, find "
                            + masterSecretKeyParameters.getClass().getName() + ", require"
                            + HIBEBB04MasterSecretKeyParameters.class.getName());
        }
        this.masterSecretKeyParameters = (HIBEBB04MasterSecretKeyParameters)masterSecretKeyParameters;
        this.publicKeyParameters = (HIBEBB04PublicKeyParameters)publicKeyParameters;
        this.ids = Arrays.copyOf(ids, ids.length);
    }

    public HIBEBB04MasterSecretKeyParameters getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public HIBEBB04PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getIdAt(int index) {
        return ids[index];
    }

    public String[] getIds() {
        return Arrays.copyOf(ids, ids.length);
    }

    public int getLength() {
        return ids.length;
    }
}

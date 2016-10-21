package cn.edu.buaa.crypto.encryption.hibe.bb04.params;

import cn.edu.buaa.crypto.algebra.params.PairingParametersGenerationParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 15-9-30.
 *
 * Secret key generation parameters for Boneh-Boyen HIBE scheme.
 */
public class HIBEBB04SecretKeyGenerationParameters extends KeyGenerationParameters {

    private HIBEBB04MasterSecretKeyParameters masterSecretKeyParameters;
    private HIBEBB04PublicKeyParameters publicKeyParameters;
    private String[] ids;

    public HIBEBB04SecretKeyGenerationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters,
            String[] ids) {
        super(null, PairingParametersGenerationParameters.STENGTH);
        this.masterSecretKeyParameters = (HIBEBB04MasterSecretKeyParameters)masterSecretKeyParameters;
        this.publicKeyParameters = (HIBEBB04PublicKeyParameters)publicKeyParameters;
        this.ids = new String[ids.length];
        System.arraycopy(ids, 0, this.ids, 0, this.ids.length);
    }

    public HIBEBB04MasterSecretKeyParameters getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public HIBEBB04PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getIdAt(int index) {
        return ids[index];
    }

    public String[] getIds() {
        return this.ids;
    }

    public int getLength() {
        return ids.length;
    }
}

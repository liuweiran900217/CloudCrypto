package cn.edu.buaa.crypto.encryption.hibe.bb04.genparams;

import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04PublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 15-10-1.
 *
 * Ciphertext generation parameters for Boneh-Boyen HIBE scheme.
 */
public class HIBEBB04CiphertextGenerationParameter implements CipherParameters {
    private HIBEBB04PublicKeySerParameter publicKeyParameters;
    private String[] ids;

    public HIBEBB04CiphertextGenerationParameter(
            CipherParameters publicKeyParameters, String[] ids) {
        this.publicKeyParameters = (HIBEBB04PublicKeySerParameter)publicKeyParameters;
        assert(ids.length <= this.publicKeyParameters.getMaxDepth());
        this.ids = ids;
    }

    public HIBEBB04PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }

    public int getLength() { return this.ids.length; }
}

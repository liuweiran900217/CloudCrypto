package cn.edu.buaa.crypto.encryption.hibe.bb04.params;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 15-10-1.
 *
 * Ciphertext generation parameters for Boneh-Boyen HIBE scheme.
 */
public class HIBEBB04CiphertextGenerationParameters implements CipherParameters {
    private HIBEBB04PublicKeySerParameter publicKeyParameters;
    private String[] ids;

    public HIBEBB04CiphertextGenerationParameters(
            CipherParameters publicKeyParameters, String[] ids) {
        this.publicKeyParameters = (HIBEBB04PublicKeySerParameter)publicKeyParameters;
        assert(ids.length <= this.publicKeyParameters.getMaxLength());
        this.ids = ids;
    }

    public HIBEBB04PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }

    public int getLength() { return this.ids.length; }
}

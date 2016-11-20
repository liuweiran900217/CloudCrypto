package cn.edu.buaa.crypto.encryption.hibe.bb04.genparams;

import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 15-10-1.
 *
 * Boneh-Boyen HIBE ciphertext generation parameter.
 */
public class HIBEBB04EncryptionGenerationParameter implements CipherParameters {
    private HIBEBB04PublicKeySerParameter publicKeyParameters;
    private String[] ids;
    private Element message;

    public HIBEBB04EncryptionGenerationParameter(CipherParameters publicKeyParameters, String[] ids, Element message) {
        this.publicKeyParameters = (HIBEBB04PublicKeySerParameter)publicKeyParameters;
        assert(ids.length <= this.publicKeyParameters.getMaxDepth());
        this.ids = ids;
        this.message = message.getImmutable();
    }

    public HIBEBB04PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }

    public int getLength() { return this.ids.length; }

    public Element getMessage() { return this.message.duplicate(); }
}

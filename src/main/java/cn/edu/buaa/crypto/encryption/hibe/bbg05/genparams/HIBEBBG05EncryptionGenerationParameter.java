package cn.edu.buaa.crypto.encryption.hibe.bbg05.genparams;

import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Boneh-Boyen-Goh HIBE encryption generation parameter.
 */
public class HIBEBBG05EncryptionGenerationParameter implements CipherParameters {
    private HIBEBBG05PublicKeySerParameter publicKeyParameters;
    private String[] ids;
    private Element message;

    public HIBEBBG05EncryptionGenerationParameter(CipherParameters publicKeyParameters, String[] ids, Element message) {
        this.publicKeyParameters = (HIBEBBG05PublicKeySerParameter)publicKeyParameters;
        assert(ids.length <= this.publicKeyParameters.getMaxLength());
        this.ids = ids;
        this.message = message.getImmutable();
    }

    public HIBEBBG05PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }

    public Element getMessage() { return this.message; }

    public int getLength() { return this.ids.length; }
}

package cn.edu.buaa.crypto.encryption.hibbe.llw14.genparams;

import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu composite-order HIBBE encryption generation parameter.
 */
public class HIBBELLW14EncryptionGenerationParameter implements CipherParameters {
    private HIBBELLW14PublicKeySerParameter publicKeyParameters;
    private String[] ids;
    private Element message;

    public HIBBELLW14EncryptionGenerationParameter(
            CipherParameters publicKeyParameters, String[] ids, Element message) {
        this.publicKeyParameters = (HIBBELLW14PublicKeySerParameter)publicKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = ids;
        this.message = message.getImmutable();
    }

    public HIBBELLW14PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }

    public Element getMessage() { return this.message.duplicate(); }
}

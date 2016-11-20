package cn.edu.buaa.crypto.encryption.hibbe.llw16a.genparams;

import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aPublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE encryption generation parameters.
 */
public class HIBBELLW16aEncryptionGenerationParameter implements CipherParameters {
    private HIBBELLW16aPublicKeySerParameter publicKeyParameters;
    private String[] ids;
    private Element message;

    public HIBBELLW16aEncryptionGenerationParameter(CipherParameters publicKeyParameters, String[] ids, Element message) {
        this.publicKeyParameters = (HIBBELLW16aPublicKeySerParameter)publicKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = ids;
        this.message = message.getImmutable();
    }

    public HIBBELLW16aPublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }

    public Element getMessage() { return this.message.duplicate(); }
}

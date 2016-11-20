package cn.edu.buaa.crypto.encryption.hibbe.llw16a.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingEncryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aPublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE encryption generation parameters.
 */
public class HIBBELLW16aEncryptionGenerationParameter extends PairingEncryptionGenerationParameter {
    private String[] ids;

    public HIBBELLW16aEncryptionGenerationParameter(PairingKeySerParameter publicKeyParameters, String[] ids, Element message) {
        super(publicKeyParameters, message);
        assert(ids.length == ((HIBBELLW16aPublicKeySerParameter)publicKeyParameters).getMaxUser());
        this.ids = ids;
    }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }
}

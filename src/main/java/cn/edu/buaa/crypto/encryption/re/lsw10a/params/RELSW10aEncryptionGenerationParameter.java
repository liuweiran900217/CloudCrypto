package cn.edu.buaa.crypto.encryption.re.lsw10a.params;

import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aPublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Waters revocation encryption ciphertext generation parameter.
 */
public class RELSW10aEncryptionGenerationParameter implements CipherParameters {
    private RELSW10aPublicKeySerParameter publicKeyParameters;
    private String[] ids;
    private Element message;

    public RELSW10aEncryptionGenerationParameter(CipherParameters publicKeyParameters, String[] ids, Element message) {
        this.publicKeyParameters = (RELSW10aPublicKeySerParameter)publicKeyParameters;
        //remove repeated ids
        this.ids = PairingUtils.removeDuplicates(ids);
        this.message = message.getImmutable();
    }

    public RELSW10aPublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }

    public int getLength() { return this.ids.length; }

    public Element getMessage() { return this.message; }
}

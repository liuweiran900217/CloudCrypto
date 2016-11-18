package cn.edu.buaa.crypto.encryption.re.lsw10a.params;

import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aPublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Waters revocation encryption ciphertext generation parameter.
 */
public class RELSW10aCiphertextGenerationParameter implements CipherParameters {
    private RELSW10aPublicKeySerParameter publicKeyParameters;
    private String[] ids;

    public RELSW10aCiphertextGenerationParameter(CipherParameters publicKeyParameters, String[] ids) {
        this.publicKeyParameters = (RELSW10aPublicKeySerParameter)publicKeyParameters;
        //remove repeated ids
        this.ids = PairingUtils.removeDuplicates(ids);
    }

    public RELSW10aPublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }

    public int getLength() { return this.ids.length; }
}

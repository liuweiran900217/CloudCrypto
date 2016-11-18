package cn.edu.buaa.crypto.encryption.re.lsw10a.params;

import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aPublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

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
        Set<String> idSet = new HashSet<String>();
        Collections.addAll(idSet, ids);
        this.ids = idSet.toArray(new String[1]);
    }

    public RELSW10aPublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }

    public int getLength() { return this.ids.length; }
}

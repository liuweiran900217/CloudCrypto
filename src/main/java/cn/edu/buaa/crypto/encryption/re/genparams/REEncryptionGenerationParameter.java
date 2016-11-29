package cn.edu.buaa.crypto.encryption.re.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingEncryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Revocation encryption ciphertext generation parameter.
 */
public class REEncryptionGenerationParameter extends PairingEncryptionGenerationParameter {
    private String[] ids;

    public REEncryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, String[] ids, Element message) {
        super(publicKeyParameter, message);
        //remove repeated ids
        this.ids = PairingUtils.removeDuplicates(ids);
    }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }

    public int getLength() { return this.ids.length; }
}

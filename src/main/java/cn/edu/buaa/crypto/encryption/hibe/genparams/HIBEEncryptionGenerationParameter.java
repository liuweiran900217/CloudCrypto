package cn.edu.buaa.crypto.encryption.hibe.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingEncryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;

/**
 * Created by Weiran Liu on 15-10-1.
 *
 * HIBE encryption generation parameter.
 */
public class HIBEEncryptionGenerationParameter extends PairingEncryptionGenerationParameter {
    private String[] ids;

    public HIBEEncryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, String[] ids, Element message) {
        super(publicKeyParameter, message);
        this.ids = ids;
    }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }

    public int getLength() { return this.ids.length; }
}

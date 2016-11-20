package cn.edu.buaa.crypto.encryption.hibe.bb04.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingEncryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;

/**
 * Created by Weiran Liu on 15-10-1.
 *
 * Boneh-Boyen HIBE ciphertext generation parameter.
 */
public class HIBEBB04EncryptionGenerationParameter extends PairingEncryptionGenerationParameter {
    private String[] ids;

    public HIBEBB04EncryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, String[] ids, Element message) {
        super(publicKeyParameter, message);
        assert(ids.length <= ((HIBEBB04PublicKeySerParameter)publicKeyParameter).getMaxDepth());
        this.ids = ids;
    }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }

    public int getLength() { return this.ids.length; }
}

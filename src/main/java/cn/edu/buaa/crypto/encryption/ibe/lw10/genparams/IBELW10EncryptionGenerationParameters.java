package cn.edu.buaa.crypto.encryption.ibe.lw10.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingEncryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;

/**
 * Created by Weiran Liu on 16/5/6.
 *
 * Lewko-Waters IBE encryption generation parameter.
 */
public class IBELW10EncryptionGenerationParameters extends PairingEncryptionGenerationParameter {
    private String id;

    public IBELW10EncryptionGenerationParameters(PairingKeySerParameter publicKeyParameter, String id, Element message) {
        super(publicKeyParameter, message);
        this.id = id;
    }

    public String getId() { return this.id; }
}

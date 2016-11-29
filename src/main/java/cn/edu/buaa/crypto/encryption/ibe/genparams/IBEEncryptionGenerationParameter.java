package cn.edu.buaa.crypto.encryption.ibe.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingEncryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Identity-Based Encryption ciphertext generation parameter.
 */
public class IBEEncryptionGenerationParameter extends PairingEncryptionGenerationParameter {
    private String id;

    public IBEEncryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, String id, Element message) {
        super(publicKeyParameter, message);
        this.id = id;
    }

    public String getId() { return this.id; }
}
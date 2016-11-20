package cn.edu.buaa.crypto.encryption.hibbe.llw17.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingEncryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.Digest;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE encryption generation parameter.
 */
public class HIBBELLW17EncryptionGenerationParameter extends PairingEncryptionGenerationParameter {
    private Digest digest;
    private String[] ids;

    public HIBBELLW17EncryptionGenerationParameter(
            Digest digest, PairingKeySerParameter publicKeyParameter, String[] ids, Element message) {
        super(publicKeyParameter, message);
        this.digest = digest;
        assert(ids.length == ((HIBBELLW17PublicKeySerParameter)publicKeyParameter).getMaxUser());
        this.ids = ids;
    }

    public Digest getDigest() { return this.digest; }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }
}

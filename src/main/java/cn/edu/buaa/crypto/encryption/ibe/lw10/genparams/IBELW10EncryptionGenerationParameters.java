package cn.edu.buaa.crypto.encryption.ibe.lw10.genparams;

import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 16/5/6.
 *
 * Lewko-Waters IBE encryption generation parameter.
 */
public class IBELW10EncryptionGenerationParameters implements CipherParameters {
    private IBELW10PublicKeySerParameter publicKeyParameters;
    private String id;
    private Element message;

    public IBELW10EncryptionGenerationParameters(CipherParameters publicKeyParameters, String id, Element message) {
        this.publicKeyParameters = (IBELW10PublicKeySerParameter)publicKeyParameters;
        this.id = id;
        this.message = message.getImmutable();
    }

    public IBELW10PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String getId() { return this.id; }

    public Element getMessage() { return this.message; }
}

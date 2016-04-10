package cn.edu.buaa.crypto.encryption.re.oolsw10a.params;

import junit.framework.Assert;
import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/4/10.
 */
public class OORELSW10aCiphertextGenerationParameters implements CipherParameters {
    private boolean isICiphertextGeneration;
    private int length;
    private OORELSW10aPublicKeyParameters publicKeyParameters;
    private OORELSW10aICiphertextParameters iCiphertextParameters;
    private String[] ids;

    public OORELSW10aCiphertextGenerationParameters(CipherParameters publicKeyParameters, String[] ids) {
        this.length = ids.length;
        this.publicKeyParameters = (OORELSW10aPublicKeyParameters)publicKeyParameters;
        this.ids = Arrays.copyOf(ids, ids.length);
        this.isICiphertextGeneration = false;
    }

    public OORELSW10aCiphertextGenerationParameters(CipherParameters publicKeyParameters, CipherParameters iCiphertextParameters, String[] ids) {
        this.publicKeyParameters = (OORELSW10aPublicKeyParameters)publicKeyParameters;
        this.iCiphertextParameters = (OORELSW10aICiphertextParameters)iCiphertextParameters;
        this.ids = Arrays.copyOf(ids, ids.length);
        this.isICiphertextGeneration = true;
        this.length = ids.length;
        assert(this.length == this.iCiphertextParameters.getLength());
    }

    public boolean isICiphertextGeneration() {
        return this.isICiphertextGeneration;
    }

    public OORELSW10aPublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public OORELSW10aICiphertextParameters getICiphertextParameters() {
        return this.iCiphertextParameters;
    }

    public String[] getIds() { return Arrays.copyOf(ids, ids.length); }

    public String getIdAt(int index) { return ids[index]; }

    public int getLength() { return this.ids.length; }
}

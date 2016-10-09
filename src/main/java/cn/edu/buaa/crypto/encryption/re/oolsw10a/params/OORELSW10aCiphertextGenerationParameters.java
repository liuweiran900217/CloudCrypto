package cn.edu.buaa.crypto.encryption.re.oolsw10a.params;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/4/10.
 *
 * Lewko-Sahai-Waters Online/Offline revocable encryption generation parameters.
 */
public class OORELSW10aCiphertextGenerationParameters implements CipherParameters {
    private int length;
    private OORELSW10aPublicKeyParameters publicKeyParameters;
    private OORELSW10aICiphertextParameters iCiphertextParameters;
    private String[] ids;

    public OORELSW10aCiphertextGenerationParameters(CipherParameters publicKeyParameters, String[] ids) {
        this.length = ids.length;
        this.publicKeyParameters = (OORELSW10aPublicKeyParameters)publicKeyParameters;
        this.ids = Arrays.copyOf(ids, ids.length);
        //do not use intermediate ciphertext
        this.iCiphertextParameters = null;
    }

    public OORELSW10aCiphertextGenerationParameters(CipherParameters publicKeyParameters, CipherParameters iCiphertextParameters, String[] ids) {
        this.publicKeyParameters = (OORELSW10aPublicKeyParameters)publicKeyParameters;
        this.ids = Arrays.copyOf(ids, ids.length);
        this.length = ids.length;
        //use intermediate ciphertext
        this.iCiphertextParameters = (OORELSW10aICiphertextParameters)iCiphertextParameters;
        assert(this.length == this.iCiphertextParameters.getLength());
    }

    public boolean isICiphertextGeneration() {
        return (this.iCiphertextParameters != null);
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

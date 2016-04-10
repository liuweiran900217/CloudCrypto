package cn.edu.buaa.crypto.encryption.re.oolsw10a.params;

import cn.edu.buaa.crypto.encryption.re.oolsw10a.OORELSW10aEngine;
import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/4/10.
 */
public class OORELSW10aDecapsulationParameters implements CipherParameters {
    private OORELSW10aPublicKeyParameters publicKeyParameters;
    private OORELSW10aSecretKeyParameters secretKeyParameters;
    private String[] ids;
    private OORELSW10aCiphertextParameters ciphertextParameters;

    public OORELSW10aDecapsulationParameters(CipherParameters publicKeyParameters,
                                             CipherParameters secretKeyParameters,
                                             String[] ids,
                                             CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (OORELSW10aPublicKeyParameters)publicKeyParameters;
        this.secretKeyParameters = (OORELSW10aSecretKeyParameters)secretKeyParameters;
        this.ids = Arrays.copyOf(ids, ids.length);
        this.ciphertextParameters = (OORELSW10aCiphertextParameters)ciphertextParameters;
        if (this.ciphertextParameters.getLength() != ids.length) {
            throw new IllegalArgumentException
                    ("Length of " + OORELSW10aEngine.SCHEME_NAME
                            + " Ciphertext and Identity Set Mismatch, Ciphertext Length = "
                            + this.ciphertextParameters.getLength() + ", Identity Vector Length = "
                            + ids.length);
        }
    }

    public OORELSW10aPublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public OORELSW10aSecretKeyParameters getSecretKeyParameters() { return this.secretKeyParameters; }

    public OORELSW10aCiphertextParameters getCiphertextParameters() { return this.ciphertextParameters; }

    public int getLength() { return this.ids.length; }

    public String[] getIds() { return Arrays.copyOf(ids, ids.length); }

    public String getIdsAt(int index) { return this.ids[index]; }
}

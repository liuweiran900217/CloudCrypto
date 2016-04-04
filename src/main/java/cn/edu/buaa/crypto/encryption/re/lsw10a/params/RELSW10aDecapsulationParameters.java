package cn.edu.buaa.crypto.encryption.re.lsw10a.params;

import cn.edu.buaa.crypto.encryption.re.lsw10a.RELSW10aEngine;
import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/4/4.
 */
public class RELSW10aDecapsulationParameters implements CipherParameters {
    private RELSW10aPublicKeyParameters publicKeyParameters;
    private RELSW10aSecretKeyParameters secretKeyParameters;
    private String[] ids;
    private RELSW10aCiphertextParameters ciphertextParameters;

    public RELSW10aDecapsulationParameters(CipherParameters publicKeyParameters,
                                           CipherParameters secretKeyParameters,
                                           String[] ids,
                                           CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (RELSW10aPublicKeyParameters)publicKeyParameters;
        this.secretKeyParameters = (RELSW10aSecretKeyParameters)secretKeyParameters;
        this.ids = Arrays.copyOf(ids, ids.length);
        this.ciphertextParameters = (RELSW10aCiphertextParameters)ciphertextParameters;
        if (this.ciphertextParameters.getLength() != ids.length) {
            throw new IllegalArgumentException
                    ("Length of " + RELSW10aEngine.SCHEME_NAME
                            + " Ciphertext and Identity Vector Mismatch, Ciphertext Length = "
                            + this.ciphertextParameters.getLength() + ", Identity Vector Length = "
                            + ids.length);
        }
    }

    public RELSW10aPublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public RELSW10aSecretKeyParameters getSecretKeyParameters() { return this.secretKeyParameters; }

    public RELSW10aCiphertextParameters getCiphertextParameters() { return this.ciphertextParameters; }

    public int getLength() { return this.ids.length; }

    public String[] getIds() { return Arrays.copyOf(ids, ids.length); }

    public String getIdsAt(int index) { return this.ids[index]; }
}

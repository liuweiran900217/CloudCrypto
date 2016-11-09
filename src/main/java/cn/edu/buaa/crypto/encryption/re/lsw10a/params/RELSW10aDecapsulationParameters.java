package cn.edu.buaa.crypto.encryption.re.lsw10a.params;

import cn.edu.buaa.crypto.encryption.re.lsw10a.RELSW10aEngine;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Waters revocation encryption decapsulation parameter.
 */
public class RELSW10aDecapsulationParameters implements CipherParameters {
    private RELSW10APublicKeySerParameter publicKeyParameters;
    private RELSW10ASecretKeySerParameter secretKeyParameters;
    private String[] ids;
    private RELSW10ACipherSerParameter ciphertextParameters;

    public RELSW10aDecapsulationParameters(CipherParameters publicKeyParameters,
                                           CipherParameters secretKeyParameters,
                                           String[] ids,
                                           CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (RELSW10APublicKeySerParameter)publicKeyParameters;
        this.secretKeyParameters = (RELSW10ASecretKeySerParameter)secretKeyParameters;
        this.ids = ids;
        this.ciphertextParameters = (RELSW10ACipherSerParameter)ciphertextParameters;
        if (this.ciphertextParameters.getLength() != ids.length) {
            throw new IllegalArgumentException
                    ("Length of " + RELSW10aEngine.SCHEME_NAME
                            + " Ciphertext and Identity Vector Mismatch, Ciphertext Length = "
                            + this.ciphertextParameters.getLength() + ", Identity Vector Length = "
                            + ids.length);
        }
    }

    public RELSW10APublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public RELSW10ASecretKeySerParameter getSecretKeyParameters() { return this.secretKeyParameters; }

    public RELSW10ACipherSerParameter getCiphertextParameters() { return this.ciphertextParameters; }

    public int getLength() { return this.ids.length; }

    public String[] getIds() { return this.ids; }

    public String getIdsAt(int index) { return this.ids[index]; }
}

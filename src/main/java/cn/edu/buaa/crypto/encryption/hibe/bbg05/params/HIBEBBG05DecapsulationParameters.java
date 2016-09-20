package cn.edu.buaa.crypto.encryption.hibe.bbg05.params;

import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Key Decapsulation parameters for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05DecapsulationParameters implements CipherParameters {
    private HIBEBBG05PublicKeyParameters publicKeyParameters;
    private HIBEBBG05SecretKeyParameters secretKeyParameters;
    private String[] ids;
    private HIBEBBG05CiphertextParameters ciphertextParameters;

    public HIBEBBG05DecapsulationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            String[] ids,
            CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (HIBEBBG05PublicKeyParameters)publicKeyParameters;
        this.secretKeyParameters = (HIBEBBG05SecretKeyParameters)secretKeyParameters;
        this.ids = Arrays.copyOf(ids, ids.length);
        this.ciphertextParameters = (HIBEBBG05CiphertextParameters)ciphertextParameters;
        if (this.ciphertextParameters.getLength() != ids.length) {
            throw new IllegalArgumentException
                    ("Length of " + HIBEBBG05Engine.SCHEME_NAME
                            + " Ciphertext and Identity Vector Mismatch, Ciphertext Length = "
                            + this.ciphertextParameters.getLength() + ", Identity Vector Length = "
                            + ids.length);
        }
    }

    public HIBEBBG05PublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public HIBEBBG05SecretKeyParameters getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public HIBEBBG05CiphertextParameters getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public int getLength() { return this.ids.length; }

    public String[] getIds() { return Arrays.copyOf(ids, ids.length); }

    public String getIdsAt(int index) { return this.ids[index]; }
}

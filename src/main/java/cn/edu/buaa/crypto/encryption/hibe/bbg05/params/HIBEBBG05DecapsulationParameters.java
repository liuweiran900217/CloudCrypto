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
    private HIBEBBG05PublicKeySerParameter publicKeyParameters;
    private HIBEBBG05SecretKeySerParameter secretKeyParameters;
    private String[] ids;
    private HIBEBBG05CipherSerParameter ciphertextParameters;

    public HIBEBBG05DecapsulationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            String[] ids,
            CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (HIBEBBG05PublicKeySerParameter)publicKeyParameters;
        this.secretKeyParameters = (HIBEBBG05SecretKeySerParameter)secretKeyParameters;
        this.ids = ids;
        this.ciphertextParameters = (HIBEBBG05CipherSerParameter)ciphertextParameters;
        if (this.ciphertextParameters.getLength() != ids.length) {
            throw new IllegalArgumentException
                    ("Length of " + HIBEBBG05Engine.SCHEME_NAME
                            + " Ciphertext and Identity Vector Mismatch, Ciphertext Length = "
                            + this.ciphertextParameters.getLength() + ", Identity Vector Length = "
                            + ids.length);
        }
    }

    public HIBEBBG05PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public HIBEBBG05SecretKeySerParameter getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public HIBEBBG05CipherSerParameter getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public int getLength() { return this.ids.length; }

    public String[] getIds() { return this.ids; }

    public String getIdsAt(int index) { return this.ids[index]; }
}

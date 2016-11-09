package cn.edu.buaa.crypto.encryption.hibe.bb04.params;

import cn.edu.buaa.crypto.encryption.hibe.bb04.HIBEBB04Engine;
import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 15-10-1.
 *
 * Delegation parameters for Boneh-Boyen HIBE scheme.
 */
public class HIBEBB04DecapsulationParameters implements CipherParameters {
    private HIBEBB04PublicKeySerParameter publicKeyParameters;
    private HIBEBB04SecretKeySerParameter secretKeyParameters;
    private String[] ids;
    private HIBEBB04CipherSerParameter ciphertextParameters;

    public HIBEBB04DecapsulationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            String[] ids,
            CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (HIBEBB04PublicKeySerParameter)publicKeyParameters;
        this.secretKeyParameters = (HIBEBB04SecretKeySerParameter)secretKeyParameters;
        this.ids = ids;
        this.ciphertextParameters = (HIBEBB04CipherSerParameter)ciphertextParameters;
        if (this.ciphertextParameters.getLength() != ids.length) {
            throw new IllegalArgumentException
                    ("Length of " + HIBEBB04Engine.SCHEME_NAME
                            + " Ciphertext and Identity Vector Mismatch, Ciphertext Length = "
                            + this.ciphertextParameters.getLength() + ", Identity Vector Length = "
                            + ids.length);
        }
    }

    public HIBEBB04PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public HIBEBB04SecretKeySerParameter getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public HIBEBB04CipherSerParameter getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public int getLength() { return this.ids.length; }

    public String[] getIds() { return this.ids; }

    public String getIdsAt(int index) { return this.ids[index]; }
}

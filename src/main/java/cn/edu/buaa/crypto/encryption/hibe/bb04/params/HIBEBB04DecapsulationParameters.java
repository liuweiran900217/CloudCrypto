package cn.edu.buaa.crypto.encryption.hibe.bb04.params;

import cn.edu.buaa.crypto.encryption.hibe.bb04.HIBEBB04Engine;
import org.bouncycastle.crypto.CipherParameters;

import java.security.InvalidParameterException;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 15-10-1.
 *
 * Delegation parameters for Boneh-Boyen HIBE scheme.
 */
public class HIBEBB04DecapsulationParameters implements CipherParameters {
    private HIBEBB04PublicKeyParameters publicKeyParameters;
    private HIBEBB04SecretKeyParameters secretKeyParameters;
    private String[] ids;
    private HIBEBB04CiphertextParameters ciphertextParameters;

    public HIBEBB04DecapsulationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            String[] ids,
            CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (HIBEBB04PublicKeyParameters)publicKeyParameters;
        this.secretKeyParameters = (HIBEBB04SecretKeyParameters)secretKeyParameters;
        this.ids = Arrays.copyOf(ids, ids.length);
        this.ciphertextParameters = (HIBEBB04CiphertextParameters)ciphertextParameters;
        if (this.ciphertextParameters.getLength() != ids.length) {
            throw new IllegalArgumentException
                    ("Length of " + HIBEBB04Engine.SCHEME_NAME
                            + " Ciphertext and Identity Vector Mismatch, Ciphertext Length = "
                            + this.ciphertextParameters.getLength() + ", Identity Vector Length = "
                            + ids.length);
        }
    }

    public HIBEBB04PublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public HIBEBB04SecretKeyParameters getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public HIBEBB04CiphertextParameters getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public int getLength() { return this.ids.length; }

    public String[] getIds() { return Arrays.copyOf(ids, ids.length); }

    public String getIdsAt(int index) { return this.ids[index]; }
}

package cn.edu.buaa.crypto.encryption.ibbe.del07.params;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Decapsulation parameters for Delerablée IBBE scheme.
 */
public class IBBEDel07DecapsulationParameters implements CipherParameters {
    private IBBEDel07PublicKeyParameters publicKeyParameters;
    private IBBEDel07SecretKeyParameters secretKeyParameters;
    private String[] ids;
    private IBBEDel07CiphertextParameters ciphertextParameters;

    public IBBEDel07DecapsulationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            String[] ids,
            CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (IBBEDel07PublicKeyParameters)publicKeyParameters;
        this.secretKeyParameters = (IBBEDel07SecretKeyParameters)secretKeyParameters;
        this.ids = Arrays.copyOf(ids, ids.length);
        this.ciphertextParameters = (IBBEDel07CiphertextParameters)ciphertextParameters;
    }

    public IBBEDel07PublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public IBBEDel07SecretKeyParameters getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public IBBEDel07CiphertextParameters getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public int getNumberOfBroadcastReceiver() { return this.ids.length; }

    public String[] getIds() { return Arrays.copyOf(ids, ids.length); }

    public String getIdsAt(int index) { return this.ids[index]; }
}

package cn.edu.buaa.crypto.encryption.ibbe.del07.params;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Decapsulation parameters for Delerablée IBBE scheme.
 */
public class IBBEDel07DecapsulationParameters implements CipherParameters {
    private IBBEDel07PublicKeySerParameter publicKeyParameters;
    private IBBEDel07SecretKeySerParameter secretKeyParameters;
    private String[] ids;
    private IBBEDel07CipherSerParameter ciphertextParameters;

    public IBBEDel07DecapsulationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters secretKeyParameters,
            String[] ids,
            CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (IBBEDel07PublicKeySerParameter)publicKeyParameters;
        this.secretKeyParameters = (IBBEDel07SecretKeySerParameter)secretKeyParameters;
        this.ids = ids;
        this.ciphertextParameters = (IBBEDel07CipherSerParameter)ciphertextParameters;
    }

    public IBBEDel07PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public IBBEDel07SecretKeySerParameter getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public IBBEDel07CipherSerParameter getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public int getNumberOfBroadcastReceiver() { return this.ids.length; }

    public String[] getIds() { return this.ids; }

    public String getIdsAt(int index) { return this.ids[index]; }
}

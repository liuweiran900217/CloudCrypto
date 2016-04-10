package cn.edu.buaa.crypto.encryption.re.oolsw10a.params;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/4/10.
 */
public class OORELSW10aICiphertextGenerationParameters implements CipherParameters {
    private OORELSW10aPublicKeyParameters publicKeyParameters;
    private int length;

    public OORELSW10aICiphertextGenerationParameters(CipherParameters publicKeyParameters, int length) {
        this.publicKeyParameters = (OORELSW10aPublicKeyParameters)publicKeyParameters;
        this.length = length;
    }

    public OORELSW10aPublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public int getLength() { return this.length; }
}

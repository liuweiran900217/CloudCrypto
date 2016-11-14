package cn.edu.buaa.crypto.encryption.re.lsw10a.params;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Sahai-Waters revocation encryption public key / master secret key pair generation parameter.
 */
public class RELSW10aKeyPairGenerationParameter extends KeyGenerationParameters {
    private PairingParameters pairingParameters;

    public RELSW10aKeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.pairingParameters = pairingParameters;
    }

    public PairingParameters getPairingParameters() { return this.pairingParameters; }
}

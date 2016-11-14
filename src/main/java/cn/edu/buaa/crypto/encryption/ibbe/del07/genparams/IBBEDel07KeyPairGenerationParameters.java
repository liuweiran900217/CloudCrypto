package cn.edu.buaa.crypto.encryption.ibbe.del07.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Public key / master secret key parameter generation parameters for Delerablée IBBE scheme.
 */
public class IBBEDel07KeyPairGenerationParameters extends KeyGenerationParameters {
    private int maxBroadcastReceiver;
    private PairingParameters pairingParameters;

    public IBBEDel07KeyPairGenerationParameters(PairingParameters pairingParameters, int maxBroadcastReceiver) {
        super(null, PairingParametersGenerationParameter.STENGTH);

        this.maxBroadcastReceiver = maxBroadcastReceiver;
        this.pairingParameters = pairingParameters;
    }

    public PairingParameters getPairingParameters() { return this.pairingParameters; }

    public int getMaxBroadcastReceiver() { return this.maxBroadcastReceiver; }
}

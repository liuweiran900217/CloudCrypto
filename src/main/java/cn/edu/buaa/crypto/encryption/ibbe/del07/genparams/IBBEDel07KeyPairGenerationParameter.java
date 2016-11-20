package cn.edu.buaa.crypto.encryption.ibbe.del07.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Public key / master secret key parameter generation parameters for Delerablée IBBE scheme.
 */
public class IBBEDel07KeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    private int maxBroadcastReceiver;

    public IBBEDel07KeyPairGenerationParameter(PairingParameters pairingParameters, int maxBroadcastReceiver) {
        super(pairingParameters);

        this.maxBroadcastReceiver = maxBroadcastReceiver;
    }

    public int getMaxBroadcastReceiver() { return this.maxBroadcastReceiver; }
}

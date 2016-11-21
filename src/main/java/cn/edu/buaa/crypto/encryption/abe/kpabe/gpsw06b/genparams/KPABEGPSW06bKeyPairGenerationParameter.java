package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Goyal-Pandey-Sahai-Waters large-universe KP-ABE with random oracles public key / master secret key generation parameter.
 */
public class KPABEGPSW06bKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {

    public KPABEGPSW06bKeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(pairingParameters);
    }
}

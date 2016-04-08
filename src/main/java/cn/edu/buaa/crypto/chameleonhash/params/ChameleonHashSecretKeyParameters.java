package cn.edu.buaa.crypto.chameleonhash.params;

import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/4/8.
 */
public abstract class ChameleonHashSecretKeyParameters extends PairingKeyParameters implements ChameleonHashParameters {

    public ChameleonHashSecretKeyParameters(boolean isPrivate, PairingParameters parameters) {
        super(isPrivate, parameters);
    }

    public abstract void setPublicKeyParameters(ChameleonHashPublicKeyParameters publicKeyParameters);

    public abstract ChameleonHashPublicKeyParameters getPublicKeyParameters();
}

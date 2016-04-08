package cn.edu.buaa.crypto.encryption.re.oolsw10a.params;

import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aSecretKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/4/5.
 */
public class OORELSW10aSecretKeyParameters extends RELSW10aSecretKeyParameters {
    public OORELSW10aSecretKeyParameters(RELSW10aSecretKeyParameters parameters) {
        super(parameters.getParameters(), parameters.getId(), parameters.getElementId(), parameters.getD0(), parameters.getD1(), parameters.getD2());
    }
}

package cn.edu.buaa.crypto.encryption.re.oolsw10a.params;

import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aMasterSecretKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/4/5.
 */
public class OORELSW10aMasterSecretKeyParameters extends RELSW10aMasterSecretKeyParameters {
    public OORELSW10aMasterSecretKeyParameters(PairingParameters pairingParameters, Element alpha, Element b, Element h) {
        super(pairingParameters, alpha, b, h);
    }
}

package cn.edu.buaa.crypto.encryption.re.oolsw10a.params;

import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aPublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/4/5.
 */
public class OORELSW10aPublicKeyParameters extends RELSW10aPublicKeyParameters {
    private CHEngine chEngine;

    public OORELSW10aPublicKeyParameters(CHEngine chEngine, RELSW10aPublicKeyParameters parameters) {
        super(parameters.getParameters(), parameters.getG(), parameters.getGb(), parameters.getGb2(), parameters.getHb(), parameters.getEggAlpha());
        this.chEngine = chEngine;
    }

    public CHEngine getCHEngine() { return this.chEngine; }
}

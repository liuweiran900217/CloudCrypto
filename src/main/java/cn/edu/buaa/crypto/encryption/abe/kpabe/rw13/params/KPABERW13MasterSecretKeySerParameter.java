package cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.params;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/7/21.
 *
 * Master Secret Key Parameters for Rouselakis-Waters KP-ABE
 */
public class KPABERW13MasterSecretKeySerParameter extends PairingKeySerParameter {
    private final Element alpha;

    public KPABERW13MasterSecretKeySerParameter(PairingParameters pairingParameters, Element alpha) {
        super(true, pairingParameters);
        this.alpha = alpha.getImmutable();
    }

    public Element getAlpha() {
        return this.alpha.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof KPABERW13MasterSecretKeySerParameter) {
            KPABERW13MasterSecretKeySerParameter that = (KPABERW13MasterSecretKeySerParameter)anObject;
            //Compare alpha
            if (!(PairingUtils.isEqualElement(this.alpha, that.getAlpha()))) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}

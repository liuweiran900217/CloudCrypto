package cn.edu.buaa.crypto.encryption.hibe.bb04.params;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 15-9-30.
 *
 * Master Secret Key Parameters for Boneh-Boyen HIBE.
 */
public class HIBEBB04MasterSecretKeySerParameter extends PairingKeySerParameter {

    private final Element g2Alpha;

    public HIBEBB04MasterSecretKeySerParameter(PairingParameters pairingParameters, Element g2Alpha) {
        super(true, pairingParameters);
        this.g2Alpha = g2Alpha.getImmutable();
    }

    public Element getG2Alpha(){
        return this.g2Alpha.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBEBB04MasterSecretKeySerParameter) {
            HIBEBB04MasterSecretKeySerParameter that = (HIBEBB04MasterSecretKeySerParameter)anObject;
            if (!(PairingUtils.isEqualElement(this.g2Alpha, that.getG2Alpha()))) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}

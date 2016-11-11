package cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.params;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

/**
 * Created by Weiran Liu on 2016/7/21.
 *
 * Secret Key Parameters for Rouselakis-Waters KP-ABE
 */
public class KPABERW13SecretKeySerParameter extends PairingKeySerParameter {
    private final AccessControlParameter accessControlParameter;
    private final Element[] k0s;
    private final Element[] k1s;
    private final Element[] k2s;

    public KPABERW13SecretKeySerParameter(PairingParameters pairingParameters, AccessControlParameter accessControlParameter, Element[] k0s, Element[] k1s, Element[] k2s) {
        super(true, pairingParameters);

        assert (accessControlParameter.getRhos().length == k0s.length);
        assert (k0s.length == k1s.length);
        assert (k1s.length == k2s.length);

        this.accessControlParameter = accessControlParameter;
        this.k0s = ElementUtils.cloneImmutable(k0s);
        this.k1s = ElementUtils.cloneImmutable(k1s);
        this.k2s = ElementUtils.cloneImmutable(k2s);
    }

    public AccessControlParameter getAccessControlParameter() {
        return this.accessControlParameter;
    }

    public Element[] getK0s() {
        return this.k0s;
    }

    public Element getK0At(int index) {
        return this.k0s[index].duplicate();
    }

    public Element[] getK1s() {
        return this.k1s;
    }

    public Element getK1At(int index) {
        return this.k1s[index].duplicate();
    }

    public Element[] getK2s() {
        return this.k2s;
    }

    public Element getK2At(int index) {
        return this.k2s[index].duplicate();
    }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof KPABERW13SecretKeySerParameter) {
            KPABERW13SecretKeySerParameter that = (KPABERW13SecretKeySerParameter)anOjbect;
            //Compare k0s
            if (!PairingUtils.isEqualElementArray(this.k0s, that.getK0s())) {
                return false;
            }
            //Compare k1s
            if (!PairingUtils.isEqualElementArray(this.k1s, that.getK1s())) {
                return false;
            }
            //Compare k2s
            if (!PairingUtils.isEqualElementArray(this.k2s, that.getK2s())) {
                return false;
            }
            //Compare AccessControlParameters
            if (!this.accessControlParameter.equals(that.getAccessControlParameter())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}

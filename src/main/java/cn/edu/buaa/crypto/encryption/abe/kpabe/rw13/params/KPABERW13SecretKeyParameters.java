package cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/7/21.
 *
 * Secret Key Parameters for Rouselakis-Waters KP-ABE
 */
public class KPABERW13SecretKeyParameters extends PairingKeyParameters {
    private final AccessControlParameter accessControlParameter;
    private final Element[] k0s;
    private final Element[] k1s;
    private final Element[] k2s;

    public KPABERW13SecretKeyParameters(PairingParameters pairingParameters, AccessControlParameter accessControlParameter, Element[] k0s, Element[] k1s, Element[] k2s) {
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
        return Arrays.copyOf(this.k0s, this.k0s.length);
    }

    public Element getK0At(int index) {
        return this.k0s[index].duplicate();
    }

    public Element[] getK1s() {
        return Arrays.copyOf(this.k1s, this.k1s.length);
    }

    public Element getK1At(int index) {
        return this.k1s[index].duplicate();
    }

    public Element[] getK2s() {
        return Arrays.copyOf(this.k2s, this.k2s.length);
    }

    public Element getK2At(int index) {
        return this.k2s[index].duplicate();
    }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof KPABERW13SecretKeyParameters) {
            KPABERW13SecretKeyParameters that = (KPABERW13SecretKeyParameters)anOjbect;
            //Compare k0s
            if (!Utils.isEqualElementArray(this.k0s, that.getK0s())) {
                return false;
            }
            //Compare k1s
            if (!Utils.isEqualElementArray(this.k1s, that.getK1s())) {
                return false;
            }
            //Compare k2s
            if (!Utils.isEqualElementArray(this.k2s, that.getK2s())) {
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

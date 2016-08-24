package cn.edu.buaa.crypto.chameleonhash.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

/**
 * Created by Weiran Liu on 2016/4/4.
 */
public abstract class ChameleonHashResultParameters implements ChameleonHashParameters {
    private Element hashMessage;
    private Element hashResult;
    private Element[] r;

    public ChameleonHashResultParameters(Element hashMessage, Element hashResult, Element... r) {
        this.hashMessage = hashMessage.getImmutable();
        this.hashResult = hashResult.getImmutable();
        this.r = ElementUtils.cloneImmutable(r);
    }

    public Element getHashMessage() { return this.hashMessage.duplicate(); }

    public Element getHashResult() { return this.hashResult.duplicate(); }

    public Element[] getRs() { return ElementUtils.cloneImmutable(this.r); }

    public Element getRiAt(int index) { return this.r[index].duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof ChameleonHashResultParameters) {
            ChameleonHashResultParameters that = (ChameleonHashResultParameters)anObject;
            //Compare hash message
            if (!PairingUtils.isEqualElement(this.hashMessage, that.getHashMessage())) {
                return false;
            }
            //Compare hash result
            if (!PairingUtils.isEqualElement(this.hashResult, that.getHashResult())) {
                return false;
            }
            //Compare rs
            if (!PairingUtils.isEqualElementArray(this.r, that.getRs())) {
                return false;
            }
            return true;
        }
        return false;
    }
}

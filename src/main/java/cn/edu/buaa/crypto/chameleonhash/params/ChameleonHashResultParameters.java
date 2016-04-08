package cn.edu.buaa.crypto.chameleonhash.params;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;
import org.bouncycastle.crypto.CipherParameters;

import java.math.BigInteger;

/**
 * Created by Weiran Liu on 2016/4/4.
 */
public class ChameleonHashResultParameters implements ChameleonHashParameters {
    private Element hashMessage;
    private Element hashResult;
    private Element[] r;

    public ChameleonHashResultParameters(Element hashMessage, Element hashResult, Element... r) {
        this.hashMessage = hashMessage;
        this.hashResult = hashResult;
        this.r = r;
    }

    public Element getHashMessage() { return this.hashMessage.duplicate(); }

    public Element getHashResult() { return this.hashResult.duplicate(); }

    public Element[] getRs() { return ElementUtils.cloneImmutable(this.r); }

    public Element getRiAt(int index) { return this.r[index].duplicate(); }
}

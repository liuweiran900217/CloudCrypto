package cn.edu.buaa.crypto.chameleonhash;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

import java.math.BigInteger;

/**
 * Created by Weiran Liu on 2016/4/4.
 */
public class ChameleonHashParameters implements CipherParameters {
    private Element hashMessage;
    private Element hashResult;
    private Element[] r;

    public ChameleonHashParameters(Element hashMessage, Element hashResult, Element... r) {
        this.hashMessage = hashMessage;
        this.hashResult = hashResult;
        this.r = r;
    }

    public Element getHashMessage() { return this.hashMessage; }

    public Element getHashResult() { return this.hashResult; }

    public Element[] getR() { return this.r; }
}

package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/9/20.
 *
 * Secret Key parameters for Rouselakis-Waters CP-ABE.
 */
public class CPABERW13SecretKeySerParameter extends PairingKeySerParameter {
    private final String[] attributes;
    private final Map<String, Integer> attributesMap;
    private final Element[] elementAttributes;
    private final Element k0;
    private final Element k1;
    private final Element[] k2s;
    private final Element[] k3s;

    public CPABERW13SecretKeySerParameter(PairingParameters pairingParameters, String[] attributes, Element[] elementAttributes,
                                          Element k0, Element k1, Element[] k2s, Element[] k3s) {
        super(true, pairingParameters);

        this.k0 = k0.getImmutable();
        this.k1 = k1.getImmutable();
        this.k2s = ElementUtils.cloneImmutable(k2s);
        this.k3s = ElementUtils.cloneImmutable(k3s);
        this.attributes = new String[attributes.length];
        System.arraycopy(attributes, 0, this.attributes, 0, this.attributes.length);
        attributesMap = new HashMap<String, Integer>();
        for (int i = 0; i < attributes.length; i++) {
            attributesMap.put(attributes[i], i);
        }
        this.elementAttributes = ElementUtils.cloneImmutable(elementAttributes);
    }

    public int getLength() {
        return this.attributes.length;
    }

    public String getAttributeAt(int index) { return this.attributes[index]; }

    public String[] getAttributes() { return this.attributes; }

    public Element getElementAttributeAt(int index) { return this.elementAttributes[index].duplicate(); }

    public int getIndexWithAttribute(String attribute) { return this.attributesMap.get(attribute); }

    public Element[] getElementAttributes() { return this.elementAttributes; }

    public Element getK0() { return this.k0.duplicate(); }

    public Element getK1() { return this.k1.duplicate(); }

    public Element getK2At(int index) { return this.k2s[index].duplicate(); }

    public Element[] getK2s() { return this.k2s; }

    public Element getK3At(int index) { return this.k3s[index].duplicate(); }

    public Element[] getK3s() { return this.k3s; }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof CPABERW13SecretKeySerParameter) {
            CPABERW13SecretKeySerParameter that = (CPABERW13SecretKeySerParameter)anOjbect;
            //Compare attributes
            if (!Arrays.equals(this.attributes, that.getAttributes())) {
                return false;
            }
            //Compare elementAttributes
            if (!PairingUtils.isEqualElementArray(this.elementAttributes, that.getElementAttributes())) {
                return false;
            }
            //Compare k0
            if (!PairingUtils.isEqualElement(this.k0, that.getK0())) {
                return false;
            }
            //Compare k1
            if (!PairingUtils.isEqualElement(this.k1, that.getK1())) {
                return false;
            }
            //Compare k2s
            if (!PairingUtils.isEqualElementArray(this.k2s, that.getK2s())) {
                return false;
            }
            //Compare k3s
            if (!PairingUtils.isEqualElementArray(this.k3s, that.getK3s())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}

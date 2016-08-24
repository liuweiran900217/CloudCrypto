package cn.edu.buaa.crypto.encryption.hibe.bb04.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 15-9-30.
 *
 * Secret Key Parameters for Boneh-Boyen HIBE.
 */
public class HIBEBB04SecretKeyParameters extends PairingKeyParameters {

    private final String[] ids;
    private final Element[] elementIds;

    private final Element d0;
    private final Element[] ds;


    public HIBEBB04SecretKeyParameters(PairingParameters pairingParameters, String[] ids, Element[] elementIds, Element d0, Element[] ds) {
        super(true, pairingParameters);

        this.d0 = d0.getImmutable();
        this.ds = ElementUtils.cloneImmutable(ds);
        this.ids = new String[ids.length];

        System.arraycopy(ids, 0, this.ids, 0, this.ids.length);
        this.elementIds = ElementUtils.cloneImmutable(elementIds);
    }

    public int getLength() { return this.ids.length; }

    public String getIdAt(int index) { return this.ids[index]; }

    public String[] getIds() { return Arrays.copyOf(ids, ids.length); }

    public Element getElementIdAt(int index) { return this.elementIds[index].duplicate(); }

    public Element[] getElementIds() { return Arrays.copyOf(elementIds, elementIds.length); }

    public Element getD0() { return this.d0.duplicate(); }

    public Element getDsAt(int index) { return this.ds[index].duplicate(); }

    public Element[] getDs() { return Arrays.copyOf(ds, ds.length); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBEBB04SecretKeyParameters) {
            HIBEBB04SecretKeyParameters that = (HIBEBB04SecretKeyParameters)anObject;
            //Compare length
            if (this.getLength() != that.getLength()) {
                return false;
            }
            //Compare ids
            if (!Arrays.equals(this.ids, that.getIds())) {
                return false;
            }
            //Compare elementIds
            if (!PairingUtils.isEqualElementArray(this.elementIds, that.getElementIds())) {
                return false;
            }
            //Compare d0
            if (!PairingUtils.isEqualElement(this.d0, that.getD0())) {
                return false;
            }
            //Compare ds
            if (!PairingUtils.isEqualElementArray(this.ds, that.getDs())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}

package cn.edu.buaa.crypto.encryption.hibe.bb04.params;

import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 15-9-30.
 */
public class HIBEBB04SecretKeyParameters extends PairingKeyParameters {

    private String[] ids;
    private Element[] ds;

    private Element d0;
    private Element[] elementIds;


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

    public Element getElementIdAt(int index) { return this.elementIds[index]; }

    public Element[] getElementIds() { return Arrays.copyOf(elementIds, elementIds.length); }

    public Element getD0() { return this.d0; }

    public Element getDsAt(int index) { return this.ds[index]; }
}

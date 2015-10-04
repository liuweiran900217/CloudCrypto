package cn.edu.buaa.crypto.encryption.hibe.bb04.params;

import cn.edu.buaa.crypto.pairingkem.params.PairingCiphertextParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 15-9-30.
 */
public class HIBEBB04CiphertextParameters extends PairingCiphertextParameters {

    private String[] ids;
    private Element[] elementIds;

    private Element B;
    private Element[] Cs;

    public HIBEBB04CiphertextParameters(PairingParameters pairingParameters, String[] ids, Element[] elementIds, Element B, Element[] Cs) {
        super(pairingParameters);
        this.ids = Arrays.copyOf(ids, ids.length);
        this.elementIds = ElementUtils.cloneImmutable(elementIds);

        this.B = B.getImmutable();
        this.Cs = ElementUtils.cloneImmutable(Cs);
    }

    public int getLength() { return this.ids.length; }

    public String getIdAt(int index) { return this.ids[index]; }

    public String[] getIds() { return Arrays.copyOf(ids, ids.length); }

    public Element getElementIdAt(int index) { return this.elementIds[index]; }

    public Element[] getElementIds() { return ElementUtils.cloneImmutable(elementIds); }

    public Element getB() { return this.B; }

    public Element getCsAt(int index) { return this.Cs[index]; }
}

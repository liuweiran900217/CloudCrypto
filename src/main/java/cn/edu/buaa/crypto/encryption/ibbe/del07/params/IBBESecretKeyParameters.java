package cn.edu.buaa.crypto.encryption.ibbe.del07.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/8/23.
 *
 * Secret Key Parameters for Delerablée IBBE.
 */
public class IBBESecretKeyParameters extends PairingKeyParameters {
    private final String id;
    private final Element elementId;

    private final Element secretKey;

    public IBBESecretKeyParameters(PairingParameters pairingParameters, String id, Element elementId, Element secretKey) {
        super(true, pairingParameters);
        this.secretKey = secretKey.getImmutable();
        this.id = id;
        this.elementId = elementId.getImmutable();
    }

    public String getId() { return this.id; }

    public Element getElementId() { return this.elementId.duplicate(); }

    public Element getSecretKey() { return this.secretKey.duplicate(); }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof IBBESecretKeyParameters) {
            IBBESecretKeyParameters that = (IBBESecretKeyParameters)anOjbect;
            //Compare id
            if (this.id.equals(that.getId())) {
                return false;
            }
            //Compare elementId
            if (!Utils.isEqualElement(this.elementId, that.getElementId())) {
                return false;
            }
            //Compare secret key
            if (!Utils.isEqualElement(this.secretKey, that.getSecretKey())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}

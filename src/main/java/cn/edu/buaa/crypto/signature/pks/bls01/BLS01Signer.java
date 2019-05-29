package cn.edu.buaa.crypto.signature.pks.bls01;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.signature.pks.PairingSigner;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.io.IOException;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * Boneh-Lynn-Shacham short signature scheme.
 */
public class BLS01Signer implements PairingSigner {
    private static final String SCHEME_NAME = "Boneh-Lynn-Shacham-01 signature scheme";

    private PairingKeySerParameter pairingKeySerParameter;

    public BLS01Signer() {

    }

    public void init(boolean forSigning, CipherParameters param) {
        if (forSigning) {
            this.pairingKeySerParameter = (BLS01SignSecretPairingKeySerParameter) param;
        } else {
            this.pairingKeySerParameter = (BLS01SignPublicPairingKeySerParameter) param;
        }
    }

    public Element[] generateSignature(byte[] message) {
        PairingParameters params = this.pairingKeySerParameter.getParameters();
        Pairing pairing = PairingFactory.getPairing(params);
        BLS01SignSecretPairingKeySerParameter secretKeyParameters = (BLS01SignSecretPairingKeySerParameter) this.pairingKeySerParameter;
        Element x = secretKeyParameters.getX();

        Element m = PairingUtils.MapByteArrayToGroup(pairing, message, PairingUtils.PairingGroupType.G1);
        Element sigma = m.powZn(x).getImmutable();

        return new Element[]{sigma};
    }

    public boolean verifySignature(byte[] message, Element... signature) {
        PairingParameters params = this.pairingKeySerParameter.getParameters();
        Pairing pairing = PairingFactory.getPairing(params);
        BLS01SignPublicPairingKeySerParameter publicKeyParameters = (BLS01SignPublicPairingKeySerParameter) this.pairingKeySerParameter;
        Element m = PairingUtils.MapByteArrayToGroup(pairing, message, PairingUtils.PairingGroupType.G1);
        Element g = publicKeyParameters.getG();
        Element v = publicKeyParameters.getV();

        Element sigma = signature[0];

        Element temp1 = pairing.pairing(sigma, g);
        Element temp2 = pairing.pairing(m, v);
        return PairingUtils.isEqualElement(temp1, temp2);
    }

    public byte[] derEncode(Element[] signElements) throws IOException {
        return ((CurveElement)signElements[0]).toBytesCompressed();
    }

    public Element[] derDecode(byte[] encoding) throws IOException {
        PairingParameters params = this.pairingKeySerParameter.getParameters();
        Pairing pairing = PairingFactory.getPairing(params);
        Element signature = pairing.getG1().newZeroElement();
        ((CurveElement)signature).setFromBytesCompressed(encoding);
        return new Element[]{
                signature,
        };
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}
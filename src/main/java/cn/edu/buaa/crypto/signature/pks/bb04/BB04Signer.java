package cn.edu.buaa.crypto.signature.pks.bb04;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.params.PairingKeyParameters;
import cn.edu.buaa.crypto.signature.pks.PairingSigner;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.*;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;

/**
 * Created by Weiran Liu on 2016/10/17.
 *
 * Boneh-Boyen short signatures.
 */
public class BB04Signer implements PairingSigner {
    private PairingKeyParameters pairingKeyParameters;

    public BB04Signer() {

    }

    public void init(boolean forSigning, CipherParameters param) {
        if (forSigning) {
            this.pairingKeyParameters = (BB04SignSecretKeyParameters)param;
        } else {
            this.pairingKeyParameters = (BB04SignPublicKeyParameters)param;
        }
    }

    public Element[] generateSignature(byte[] message) {
        PairingParameters params = this.pairingKeyParameters.getParameters();
        Pairing pairing = PairingFactory.getPairing(params);
        BB04SignSecretKeyParameters secretKeyParameters = (BB04SignSecretKeyParameters)this.pairingKeyParameters;
        Element x = secretKeyParameters.getX();
        Element y = secretKeyParameters.getY();
        Element g1 = secretKeyParameters.getPublicKeyParameters().getG1();

        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element m = PairingUtils.MapToZr(pairing, message);
        Element sigma = g1.powZn(y.mulZn(r).add(m).add(x).invert()).getImmutable();

        return new Element[]{sigma, r};
    }

    public boolean verifySignature(byte[] message, Element... signature) {
        PairingParameters params = this.pairingKeyParameters.getParameters();
        Pairing pairing = PairingFactory.getPairing(params);
        BB04SignPublicKeyParameters publicKeyParameters = (BB04SignPublicKeyParameters)this.pairingKeyParameters;
        Element m = PairingUtils.MapToZr(pairing, message);
        Element g1 = publicKeyParameters.getG1();
        Element g2 = publicKeyParameters.getG2();
        Element u = publicKeyParameters.getU();
        Element v = publicKeyParameters.getV();

        Element sigma = signature[0];
        Element r = signature[1];

        Element temp1 = pairing.pairing(g1, g2);
        Element temp2 = pairing.pairing(sigma, u.mul(g2.powZn(m)).mul(v.powZn(r)));
        return PairingUtils.isEqualElement(temp1,temp2);
    }

    public byte[] derEncode(Element[] signElements) throws IOException {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERPrintableString(Hex.toHexString(signElements[0].toBytes())));
        v.add(new DERPrintableString(Hex.toHexString(signElements[1].toBytes())));
        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    public Element[] derDecode(byte[] encoding) throws IOException {
        ASN1Sequence s = (ASN1Sequence)ASN1Primitive.fromByteArray(encoding);
        PairingParameters params = this.pairingKeyParameters.getParameters();
        Pairing pairing = PairingFactory.getPairing(params);

        return new Element[] {
                pairing.getG1().newElementFromBytes(Hex.decode(((ASN1String)s.getObjectAt(0)).getString())),
                pairing.getZr().newElementFromBytes(Hex.decode(((ASN1String)s.getObjectAt(1)).getString())),
        };
    }
}

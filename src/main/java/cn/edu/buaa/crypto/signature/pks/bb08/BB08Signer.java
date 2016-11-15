package cn.edu.buaa.crypto.signature.pks.bb08;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.signature.pks.PairingSigner;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Boneh-Boyen 2008 signer.
 */
public class BB08Signer implements PairingSigner {
    private transient PairingKeySerParameter pairingKeySerParameter;

    public BB08Signer() {

    }

    public void init(boolean forSigning, CipherParameters param) {
        if (forSigning) {
            this.pairingKeySerParameter = (BB08SignSecretKeySerParameter) param;
        } else {
            this.pairingKeySerParameter = (BB08SignPublicKeySerParameter) param;
        }
    }

    public Element[] generateSignature(byte[] message) {
        PairingParameters params = this.pairingKeySerParameter.getParameters();
        Pairing pairing = PairingFactory.getPairing(params);
        BB08SignSecretKeySerParameter secretKeyParameters = (BB08SignSecretKeySerParameter) this.pairingKeySerParameter;
        Element x = secretKeyParameters.getX().getImmutable();
        Element y = secretKeyParameters.getY().getImmutable();
        Element g1 = secretKeyParameters.getG1().getImmutable();

        Element m = PairingUtils.MapByteArrayToGroup(pairing, message, PairingUtils.PairingGroupType.Zr);
        Element r;
        do {
            r = pairing.getZr().newRandomElement().getImmutable();
        } while (x.add(m).div(y).negate().equals(r));

        Element sigma = g1.powZn(y.mulZn(r).add(m).add(x).invert()).getImmutable();

        return new Element[]{sigma, r};
    }

    public boolean verifySignature(byte[] message, Element... signature) {
        PairingParameters params = this.pairingKeySerParameter.getParameters();
        Pairing pairing = PairingFactory.getPairing(params);
        BB08SignPublicKeySerParameter publicKeyParameters = (BB08SignPublicKeySerParameter) this.pairingKeySerParameter;
        Element m = PairingUtils.MapByteArrayToGroup(pairing, message, PairingUtils.PairingGroupType.Zr);
        Element g2 = publicKeyParameters.getG2();
        Element u = publicKeyParameters.getU();
        Element v = publicKeyParameters.getV();
        Element z = publicKeyParameters.getZ();

        Element sigma = signature[0];
        Element r = signature[1];

        Element temp = pairing.pairing(sigma, u.mul(g2.powZn(m)).mul(v.powZn(r)));
        return PairingUtils.isEqualElement(temp, z);
    }

    public byte[] derEncode(Element[] signElements) throws IOException {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERPrintableString(Hex.toHexString(signElements[0].toBytes())));
        v.add(new DERPrintableString(Hex.toHexString(signElements[1].toBytes())));
        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    public Element[] derDecode(byte[] encoding) throws IOException {
        ASN1Sequence s = (ASN1Sequence) ASN1Primitive.fromByteArray(encoding);
        PairingParameters params = this.pairingKeySerParameter.getParameters();
        Pairing pairing = PairingFactory.getPairing(params);

        return new Element[]{
                pairing.getG1().newElementFromBytes(Hex.decode(((ASN1String) s.getObjectAt(0)).getString())),
                pairing.getZr().newElementFromBytes(Hex.decode(((ASN1String) s.getObjectAt(1)).getString())),
        };
    }
}
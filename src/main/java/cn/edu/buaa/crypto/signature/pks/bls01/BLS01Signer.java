package cn.edu.buaa.crypto.signature.pks.bls01;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.signature.pks.PairingSigner;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * Boneh-Lynn-Shacham short signature scheme.
 */
public class BLS01Signer implements PairingSigner {
    private transient PairingKeySerParameter pairingKeySerParameter;

    public BLS01Signer() {

    }

    public void init(boolean forSigning, CipherParameters param) {
        if (forSigning) {
            this.pairingKeySerParameter = (BLS01SignSecretKeySerParameter) param;
        } else {
            this.pairingKeySerParameter = (BLS01SignPublicKeySerParameter) param;
        }
    }

    public Element[] generateSignature(byte[] message) {
        PairingParameters params = this.pairingKeySerParameter.getParameters();
        Pairing pairing = PairingFactory.getPairing(params);
        BLS01SignSecretKeySerParameter secretKeyParameters = (BLS01SignSecretKeySerParameter) this.pairingKeySerParameter;
        Element x = secretKeyParameters.getX();

        Element m = PairingUtils.MapByteArrayToGroup(pairing, message, PairingUtils.PairingGroupType.G2);
        Element sigma = m.powZn(x).getImmutable();

        return new Element[]{sigma};
    }

    public boolean verifySignature(byte[] message, Element... signature) {
        PairingParameters params = this.pairingKeySerParameter.getParameters();
        Pairing pairing = PairingFactory.getPairing(params);
        BLS01SignPublicKeySerParameter publicKeyParameters = (BLS01SignPublicKeySerParameter) this.pairingKeySerParameter;
        Element m = PairingUtils.MapByteArrayToGroup(pairing, message, PairingUtils.PairingGroupType.G2);
        Element g = publicKeyParameters.getG();
        Element v = publicKeyParameters.getV();

        Element sigma = signature[0];

        Element temp1 = pairing.pairing(g, sigma);
        Element temp2 = pairing.pairing(v, m);
        return PairingUtils.isEqualElement(temp1, temp2);
    }

    public byte[] derEncode(Element[] signElements) throws IOException {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERPrintableString(Hex.toHexString(signElements[0].toBytes())));
        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    public Element[] derDecode(byte[] encoding) throws IOException {
        ASN1Sequence s = (ASN1Sequence) ASN1Primitive.fromByteArray(encoding);
        PairingParameters params = this.pairingKeySerParameter.getParameters();
        Pairing pairing = PairingFactory.getPairing(params);

        return new Element[]{
                pairing.getG2().newElementFromBytes(Hex.decode(((ASN1String) s.getObjectAt(0)).getString())),
        };
    }
}
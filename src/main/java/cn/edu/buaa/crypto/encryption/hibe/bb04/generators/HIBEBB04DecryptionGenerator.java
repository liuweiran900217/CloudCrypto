package cn.edu.buaa.crypto.encryption.hibe.bb04.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingDecapsulationGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04SecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.genparams.HIBEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 15-10-1.
 *
 * Boneh-Boyen HIBE decryption generator.
 */
public class HIBEBB04DecryptionGenerator implements PairingDecryptionGenerator, PairingDecapsulationGenerator {
    private HIBEDecryptionGenerationParameter params;

    private Element sessionKey;

    public void init(CipherParameters params) {
        this.params = (HIBEDecryptionGenerationParameter)params;
    }

    private void computeDecapsulation() throws InvalidCipherTextException {
        HIBEBB04PublicKeySerParameter publicKeyParameters = (HIBEBB04PublicKeySerParameter)this.params.getPublicKeyParameter();
        HIBEBB04SecretKeySerParameter secretKeyParameters = (HIBEBB04SecretKeySerParameter)this.params.getSecretKeyParameter();
        HIBEBB04HeaderSerParameter ciphertextParameters = (HIBEBB04HeaderSerParameter)this.params.getCiphertextParameter();

        int secretKeyLength = secretKeyParameters.getLength();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element[] elementIdsCT = PairingUtils.MapStringArrayToGroup(pairing, this.params.getIds(), PairingUtils.PairingGroupType.Zr);

        for (int i = 0; i < secretKeyLength; i++){
            if (!secretKeyParameters.getElementIdAt(i).equals(elementIdsCT[i])){
                throw new InvalidCipherTextException("Secret Key identity vector does not match Ciphertext identity vector");
            }
        }

        Element d0 = secretKeyParameters.getD0().getImmutable();
        Element B = ciphertextParameters.getB().getImmutable();
        Element[] Cs = ciphertextParameters.getCs();
        Element[] ds = new Element[Cs.length];

        Element temp1 = pairing.getGT().newOneElement().getImmutable();
        for (int i=0; i<Cs.length; i++){
            if (i < secretKeyLength) {
                ds[i] = secretKeyParameters.getDsAt(i).getImmutable();
            } else {
                d0 = d0.mul(publicKeyParameters.getG1().powZn(elementIdsCT[i]).mul(publicKeyParameters.getHsAt(i))).getImmutable();
                ds[i] = publicKeyParameters.getG().getImmutable();
            }
            temp1 = temp1.mul(pairing.pairing(Cs[i], ds[i])).getImmutable();
        }
        Element temp0 = pairing.pairing(B, d0).getImmutable();
        this.sessionKey = temp0.div(temp1).getImmutable();
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        computeDecapsulation();
        HIBEBB04CiphertextSerParameter ciphertextParameters = (HIBEBB04CiphertextSerParameter)this.params.getCiphertextParameter();
        return ciphertextParameters.getA().div(sessionKey).getImmutable();
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        computeDecapsulation();
        return this.sessionKey.toBytes();
    }
}

package cn.edu.buaa.crypto.encryption.hibbe.llw16b.generators;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.genparams.HIBBELLW16bEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bPublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE encryption generator.
 */
public class HIBBELLW16bEncryptionGenerator implements PairingEncryptionGenerator {
    private HIBBELLW16bEncryptionGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (HIBBELLW16bEncryptionGenerationParameter)params;
    }

    public PairingCipherSerParameter generateCiphertext() {
        //get sign key
        Signer signer = params.getSigner();
        AsymmetricKeySerPairGenerator signKeyPairGenerator = params.getSignKeyPairGenerator();
        signKeyPairGenerator.init(params.getSignKeyGenerationParameters());
        AsymmetricKeySerPair signKeySerPair = signKeyPairGenerator.generateKeyPair();
        AsymmetricKeySerParameter signPublicKey = signKeySerPair.getPublic();
        AsymmetricKeySerParameter signSecretKey = signKeySerPair.getPrivate();

        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(signPublicKey);
            byte[] byteArraySignPublicKey = byteArrayOutputStream.toByteArray();
            objectOutputStream.close();
            byteArrayOutputStream.close();

            HIBBELLW16bPublicKeySerParameter publicKeyParameters = this.params.getPublicKeyParameters();
            if (this.params.getIds().length != publicKeyParameters.getMaxUser()) {
                throw new IllegalArgumentException("Invalid identity vector set length");
            }
            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            String[] ids = this.params.getIds();
            Element[] elementIds = PairingUtils.MapStringArrayToGroup(pairing, ids, PairingUtils.PairingGroupType.Zr);
            Element elementVk = PairingUtils.MapByteArrayToGroup(pairing, byteArraySignPublicKey, PairingUtils.PairingGroupType.Zr);

            Element beta = pairing.getZr().newRandomElement().getImmutable();
            Element sessionKey = pairing.pairing(publicKeyParameters.getG1(), publicKeyParameters.getG2()).powZn(beta).getImmutable();
            Element C2 = sessionKey.mul(this.params.getMessage()).getImmutable();

            Element C0 = publicKeyParameters.getG().powZn(beta).getImmutable();
            Element C1 = publicKeyParameters.getG3().getImmutable();
            for (int i = 0; i < publicKeyParameters.getMaxUser(); i++) {
                if (ids[i] != null) {
                    C1 = C1.mul(publicKeyParameters.getUsAt(i).powZn(elementIds[i])).getImmutable();
                }
            }
            C1 = C1.mul(publicKeyParameters.getUv().powZn(elementVk)).getImmutable();
            C1 = C1.powZn(beta).getImmutable();

            byte[] byteArrayC0 = C0.toBytes();
            byte[] byteArrayC1 = C1.toBytes();
            byte[] byteArrayC2 = C2.toBytes();
            signer.init(true, signSecretKey);
            signer.update(byteArrayC0, 0, byteArrayC0.length);
            signer.update(byteArrayC1, 0, byteArrayC1.length);
            signer.update(byteArrayC2, 0, byteArrayC2.length);
            byte[] signature = signer.generateSignature();

            return new HIBBELLW16bCipherSerParameter(publicKeyParameters.getParameters(), signPublicKey, signature, C0, C1, C2);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        } catch (CryptoException e) {
            e.printStackTrace();
            return null;
        }
    }
}
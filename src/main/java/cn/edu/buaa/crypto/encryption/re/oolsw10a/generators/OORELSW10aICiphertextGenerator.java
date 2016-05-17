package cn.edu.buaa.crypto.encryption.re.oolsw10a.generators;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashAsymmetricCipherKeyPair;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashPublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashResultParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aICiphertextGenerationParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aICiphertextParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aPublicKeyParameters;
import cn.edu.buaa.crypto.pairingkem.generators.PairingKeyEncapsulationPairGenerator;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/4/10.
 */
public class OORELSW10aICiphertextGenerator implements PairingKeyEncapsulationPairGenerator {
    private OORELSW10aICiphertextGenerationParameters params;

    public void init(CipherParameters params) {
        this.params = (OORELSW10aICiphertextGenerationParameters)params;
    }

    public PairingKeyEncapsulationPair generateEncryptionPair() {
        OORELSW10aPublicKeyParameters publicKeyParameters = this.params.getPublicKeyParameters();
        int length = this.params.getLength();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        CHEngine chEngine = publicKeyParameters.getCHEngine();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        Element[] C1s = new Element[length];
        Element[] C2s = new Element[length];
        Element[] Is = new Element[length];
        Element[] ss = new Element[length];
        Element sv = pairing.getZr().newRandomElement().getImmutable();
        Element s = sv.duplicate().getImmutable();
        try {
            for (int i=0; i<length; i++) {
                Is[i] = Utils.MapToFirstHalfZr(pairing, pairing.getZr().newRandomElement().toBytes());
                ss[i] = pairing.getZr().newRandomElement().getImmutable();
                s = s.add(ss[i]).getImmutable();
                byteArrayOutputStream.write(Is[i].toBytes());
            }
            ChameleonHashAsymmetricCipherKeyPair chameleonHashAsymmetricCipherKeyPair = chEngine.keyGen(publicKeyParameters.getParameters());
            ChameleonHashPublicKeyParameters chameleonHashPublicKeyParameters = chameleonHashAsymmetricCipherKeyPair.getPublic();
            ChameleonHashSecretKeyParameters chameleonHashSecretKeyParameters = chameleonHashAsymmetricCipherKeyPair.getPrivate();
            ChameleonHashResultParameters chameleonHashResultParameters = chEngine.chameleonHash(chameleonHashPublicKeyParameters, byteArrayOutputStream.toByteArray());
            byteArrayOutputStream.reset();
            byteArrayOutputStream.write(chameleonHashResultParameters.getHashResult().toBytes());
            byteArrayOutputStream.write(chameleonHashPublicKeyParameters.toBytes());
            Element Iv = Utils.MapToSecondHalfZr(pairing, byteArrayOutputStream.toByteArray()).getImmutable();
            byteArrayOutputStream.close();
            Element[] rs = chameleonHashResultParameters.getRs();
            Element C0 = publicKeyParameters.getG().powZn(s).getImmutable();
            for (int i=0; i<length; i++) {
                C1s[i] = publicKeyParameters.getGb().powZn(ss[i]).getImmutable();
                C2s[i] = publicKeyParameters.getGb2().powZn(Is[i]).mul(publicKeyParameters.getHb()).powZn(ss[i]).getImmutable();
            }
            Element Cv1 = publicKeyParameters.getGb().powZn(sv).getImmutable();
            Element Cv2 = publicKeyParameters.getGb2().powZn(Iv).mul(publicKeyParameters.getHb()).powZn(sv).getImmutable();
            Element sessionKey = publicKeyParameters.getEggAlpha().powZn(s).getImmutable();
            byte[] byteArraySessionKey = sessionKey.toBytes();

            return new PairingKeyEncapsulationPair(
                    Arrays.copyOf(byteArraySessionKey, byteArraySessionKey.length),
                    new OORELSW10aICiphertextParameters(publicKeyParameters.getParameters(), length,
                            C0, C1s, C2s, Cv1, Cv2, Is, Iv, ss, sv, s, sessionKey,
                            chameleonHashSecretKeyParameters, chameleonHashResultParameters)
            );
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}

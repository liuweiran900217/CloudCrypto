package cn.edu.buaa.crypto.encryption.re.oolsw10a.generators;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashAsymmetricCipherKeyPair;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashPublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashResultParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aCiphertextGenerationParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aCiphertextParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aICiphertextParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aPublicKeyParameters;
import cn.edu.buaa.crypto.pairingkem.generator.PairingKeyEncapsulationPairGenerator;
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
public class OORELSW10aKeyEncapsulationPairGenerator implements PairingKeyEncapsulationPairGenerator {
    private OORELSW10aCiphertextGenerationParameters params;

    public void init(CipherParameters params) {
        this.params = (OORELSW10aCiphertextGenerationParameters)params;
    }

    public PairingKeyEncapsulationPair generateEncryptionPair() {
        OORELSW10aPublicKeyParameters publicKeyParameters = this.params.getPublicKeyParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        CHEngine chEngine = publicKeyParameters.getCHEngine();
        String[] ids = this.params.getIds();
        Element[] elementIds = Utils.MapToFirstHalfZr(pairing, ids);
        if (this.params.isICiphertextGeneration()) {
            //Generate ciphertext with intermediate ciphertext
            try {
                OORELSW10aICiphertextParameters iCiphertextParameters = this.params.getICiphertextParameters();
                Element[] Imalls = new Element[this.params.getLength()];
                for (int i=0; i<this.params.getLength(); i++) {
                    Imalls[i] = elementIds[i].sub(iCiphertextParameters.getIAt(i)).mulZn(iCiphertextParameters.getSsAt(i)).getImmutable();
                }
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                byteArrayOutputStream.write(iCiphertextParameters.getC0().toBytes());
                for (int i=0; i<this.params.getLength(); i++) {
                    byteArrayOutputStream.write(iCiphertextParameters.getC1At(i).toBytes());
                    byteArrayOutputStream.write(iCiphertextParameters.getC2At(i).toBytes());
                }
                byteArrayOutputStream.write(iCiphertextParameters.getCv1().toBytes());
                byteArrayOutputStream.write(iCiphertextParameters.getCv2().toBytes());
                for (int i=0; i<this.params.getLength(); i++) {
                    byteArrayOutputStream.write(Imalls[i].toBytes());
                }
                ChameleonHashResultParameters chameleonHashResultParameters = chEngine.collision(iCiphertextParameters.getChameleonHashSecretKey(),
                        iCiphertextParameters.getChameleonHashResut(), byteArrayOutputStream.toByteArray());
                byteArrayOutputStream.close();
                return new PairingKeyEncapsulationPair(iCiphertextParameters.getSessionKey().toBytes(),
                        new OORELSW10aCiphertextParameters(publicKeyParameters.getParameters(), this.params.getLength(),
                                iCiphertextParameters.getC0(), iCiphertextParameters.getC1s(), iCiphertextParameters.getC2s(),
                                Imalls, iCiphertextParameters.getCv1(), iCiphertextParameters.getCv2(),
                                iCiphertextParameters.getChameleonHashSecretKey().getPublicKeyParameters(),
                                chameleonHashResultParameters));
            } catch (IOException e) {
                e.printStackTrace();
                return null;
            }
        } else {
            //Generate ciphertext without intermediate ciphertext
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            Element[] C1s = new Element[this.params.getLength()];
            Element[] C2s = new Element[this.params.getLength()];
            Element[] ss = new Element[this.params.getLength()];
            Element sv = pairing.getZr().newRandomElement().getImmutable();
            Element s = sv.duplicate().getImmutable();
            try {
                for (int i = 0; i < this.params.getLength(); i++) {
                    ss[i] = pairing.getZr().newRandomElement().getImmutable();
                    s = s.add(ss[i]).getImmutable();
                    byteArrayOutputStream.write(elementIds[i].toBytes());
                }
                ChameleonHashAsymmetricCipherKeyPair chameleonHashAsymmetricCipherKeyPair = chEngine.keyGen(publicKeyParameters.getParameters());
                ChameleonHashPublicKeyParameters chameleonHashPublicKeyParameters = chameleonHashAsymmetricCipherKeyPair.getPublic();
                ChameleonHashSecretKeyParameters chameleonHashSecretKeyParameters = chameleonHashAsymmetricCipherKeyPair.getPrivate();
                ChameleonHashResultParameters chameleonHashResultParameters = chEngine.chameleonHash(chameleonHashPublicKeyParameters, byteArrayOutputStream.toByteArray());
                byteArrayOutputStream.reset();
                byteArrayOutputStream.write(chameleonHashResultParameters.getHashResult().toBytes());
                byteArrayOutputStream.write(chameleonHashPublicKeyParameters.toBytes());
                Element Iv = Utils.MapToSecondHalfZr(pairing, byteArrayOutputStream.toByteArray()).getImmutable();
                byteArrayOutputStream.reset();
                Element[] rs = chameleonHashResultParameters.getRs();
                Element C0 = publicKeyParameters.getG().powZn(s).getImmutable();
                for (int i = 0; i < this.params.getLength(); i++) {
                    C1s[i] = publicKeyParameters.getGb().powZn(ss[i]).getImmutable();
                    C2s[i] = publicKeyParameters.getGb2().powZn(elementIds[i]).mul(publicKeyParameters.getHb()).powZn(ss[i]).getImmutable();
                }
                Element Cv1 = publicKeyParameters.getGb().powZn(sv).getImmutable();
                Element Cv2 = publicKeyParameters.getGb2().powZn(Iv).mul(publicKeyParameters.getHb()).powZn(sv).getImmutable();
                Element sessionKey = publicKeyParameters.getEggAlpha().powZn(s).getImmutable();
                byte[] byteArraySessionKey = sessionKey.toBytes();
                byteArrayOutputStream.write(C0.toBytes());
                for (int i=0; i<this.params.getLength(); i++) {
                    byteArrayOutputStream.write(C1s[i].toBytes());
                    byteArrayOutputStream.write(C2s[i].toBytes());
                }
                byteArrayOutputStream.write(Cv1.toBytes());
                byteArrayOutputStream.write(Cv2.toBytes());
                for (int i=0; i<this.params.getLength(); i++) {
                    byteArrayOutputStream.write(pairing.getZr().newZeroElement().toBytes());
                }
                chameleonHashResultParameters = chEngine.collision(chameleonHashSecretKeyParameters,
                        chameleonHashResultParameters, byteArrayOutputStream.toByteArray());
                byteArrayOutputStream.close();

                return new PairingKeyEncapsulationPair(
                        Arrays.copyOf(byteArraySessionKey, byteArraySessionKey.length),
                        new OORELSW10aCiphertextParameters(publicKeyParameters.getParameters(), this.params.getLength(),
                                C0, C1s, C2s, Cv1, Cv2,
                                chameleonHashPublicKeyParameters, chameleonHashResultParameters)
                );
            } catch (IOException e) {
                e.printStackTrace();
                return null;
            }
        }
    }
}

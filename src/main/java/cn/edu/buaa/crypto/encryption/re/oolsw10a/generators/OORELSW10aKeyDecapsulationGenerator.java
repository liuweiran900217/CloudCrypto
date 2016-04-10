package cn.edu.buaa.crypto.encryption.re.oolsw10a.generators;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashResultParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aCiphertextParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aDecapsulationParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aPublicKeyParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aSecretKeyParameters;
import cn.edu.buaa.crypto.pairingkem.generator.PairingKeyDecapsulationGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/4/10.
 */
public class OORELSW10aKeyDecapsulationGenerator implements PairingKeyDecapsulationGenerator {
    private OORELSW10aDecapsulationParameters params;

    public void init(CipherParameters params) {
        this.params = (OORELSW10aDecapsulationParameters)params;
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        OORELSW10aPublicKeyParameters publicKeyParameters = this.params.getPublicKeyParameters();
        OORELSW10aSecretKeyParameters secretKeyParameters = this.params.getSecretKeyParameters();
        OORELSW10aCiphertextParameters ciphertextParameters = this.params.getCiphertextParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element[] elementIds = Utils.MapToFirstHalfZr(pairing, this.params.getIds());
        Element[] recoverC2s = new Element[this.params.getLength()];

        for (int i=0; i<elementIds.length; i++){
            if (Utils.isEqualElement(secretKeyParameters.getElementId(), elementIds[i])) {
                throw new InvalidCipherTextException("identity associated with the secret key is in the revocation list of the ciphertext");
            }
        }

        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byteArrayOutputStream.write(ciphertextParameters.getC0().toBytes());
            for (int i = 0; i < this.params.getLength(); i++) {
                byteArrayOutputStream.write(ciphertextParameters.getC1At(i).toBytes());
                byteArrayOutputStream.write(ciphertextParameters.getC2At(i).toBytes());
            }
            byteArrayOutputStream.write(ciphertextParameters.getCv1().toBytes());
            byteArrayOutputStream.write(ciphertextParameters.getCv2().toBytes());
            for (int i = 0; i < this.params.getLength(); i++) {
                byteArrayOutputStream.write(ciphertextParameters.getImallAt(i).toBytes());
            }
            ChameleonHashResultParameters chameleonHashResultParameters = publicKeyParameters.getCHEngine().chameleonHash(
                    ciphertextParameters.getChameleonHashPublicKeyParameters(), byteArrayOutputStream.toByteArray(),
                    ciphertextParameters.getChameleonHashResultParameters().getRs());
            byteArrayOutputStream.reset();

            if (!chameleonHashResultParameters.getHashResult().equals(ciphertextParameters.getChameleonHashResultParameters().getHashResult())) {
                return null;
            }
            byteArrayOutputStream.write(chameleonHashResultParameters.getHashResult().toBytes());
            byteArrayOutputStream.write(ciphertextParameters.getChameleonHashPublicKeyParameters().toBytes());
            Element Iv = Utils.MapToSecondHalfZr(pairing, byteArrayOutputStream.toByteArray()).getImmutable();
            byteArrayOutputStream.close();

            for (int i = 0; i < this.params.getLength(); i++) {
                recoverC2s[i] = ciphertextParameters.getC2At(i).mul(publicKeyParameters.getGb2().powZn(ciphertextParameters.getImallAt(i))).getImmutable();
            }

            //Ciphertext verification\
            Element[] tau_i = new Element[this.params.getLength()];
            Element tau_0 = pairing.getZr().newRandomElement().getImmutable();
            //Equality (5)
            Element mulTemp0 = ciphertextParameters.getCv2().powZn(tau_0).getImmutable();
            Element mulTemp1 = ciphertextParameters.getCv1().powZn(tau_0.mul(Iv)).getImmutable();
            Element mulTemp2 = ciphertextParameters.getCv1().powZn(tau_0).getImmutable();
            //Equality (3)
            Element mulTemp3 = ciphertextParameters.getCv1().getImmutable();
            for (int i=0; i<this.params.getLength(); i++){
                tau_i[i] = pairing.getZr().newRandomElement().getImmutable();
                mulTemp0 = mulTemp0.mul(recoverC2s[i].powZn(tau_i[i])).getImmutable();
                mulTemp1 = mulTemp1.mul(ciphertextParameters.getC1At(i).powZn(tau_i[i].mul(elementIds[i]))).getImmutable();
                mulTemp2 = mulTemp2.mul(ciphertextParameters.getC1At(i).powZn(tau_i[i])).getImmutable();
                mulTemp3 = mulTemp3.mul(ciphertextParameters.getC1At(i)).getImmutable();
            }
            Element p0 = pairing.pairing(publicKeyParameters.getGb(), mulTemp0).getImmutable();
            Element p1 = pairing.pairing(publicKeyParameters.getGb2(), mulTemp1).getImmutable();
            Element p2 = pairing.pairing(publicKeyParameters.getHb(), mulTemp2).getImmutable();
            p1 = p1.mul(p2).getImmutable();

            Element p3 = pairing.pairing(publicKeyParameters.getG(), mulTemp3).getImmutable();
            Element p4 = pairing.pairing(ciphertextParameters.getC0(), publicKeyParameters.getGb()).getImmutable();
            //Test Equality (5)
            if (!Utils.isEqualElement(p0, p1)) {
                System.out.println("Equality 5");
                return null;
            }
            //Test Equality (3)
            if (!Utils.isEqualElement(p3, p4)) {
                return null;
            }

            //decrypt
            Element C1 = ciphertextParameters.getCv1().powZn(secretKeyParameters.getElementId().sub(Iv).invert()).getImmutable();
            Element C2 = ciphertextParameters.getCv2().powZn(secretKeyParameters.getElementId().sub(Iv).invert()).getImmutable();
            for (int i = 0; i < ciphertextParameters.getLength(); i++) {
                C1 = C1.mul(ciphertextParameters.getC1At(i).powZn(secretKeyParameters.getElementId().sub(elementIds[i]).invert())).getImmutable();
                C2 = C2.mul(recoverC2s[i].powZn(secretKeyParameters.getElementId().sub(elementIds[i]).invert())).getImmutable();
            }
            Element sessionKey = pairing.pairing(ciphertextParameters.getC0(), secretKeyParameters.getD0())
                    .mul(pairing.pairing(secretKeyParameters.getD1(), C1).mul(pairing.pairing(secretKeyParameters.getD2(), C2)).invert()).getImmutable();
            byte[] byteArraySessionKey = sessionKey.toBytes();
            return Arrays.copyOf(byteArraySessionKey, byteArraySessionKey.length);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}

package cn.edu.buaa.crypto.encryption.ibbe.del07.generators;

import cn.edu.buaa.crypto.algebra.HornerRule;
import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.encryption.ibbe.del07.params.IBBEDel07CiphertextParameters;
import cn.edu.buaa.crypto.encryption.ibbe.del07.params.IBBEDel07DecapsulationParameters;
import cn.edu.buaa.crypto.encryption.ibbe.del07.params.IBBEDel07PublicKeyParameters;
import cn.edu.buaa.crypto.encryption.ibbe.del07.params.IBBEDel07SecretKeyParameters;
import cn.edu.buaa.crypto.pairingkem.generators.PairingKeyDecapsulationGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Key decapsulation generator for Delerablée IBBE scheme.
 */
public class IBBEDel07KeyDecapsulationGenerator implements PairingKeyDecapsulationGenerator {
    private IBBEDel07DecapsulationParameters params;

    public void init(CipherParameters params) {
        this.params = (IBBEDel07DecapsulationParameters)params;
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        IBBEDel07PublicKeyParameters publicKeyParameters = this.params.getPublicKeyParameters();
        IBBEDel07SecretKeyParameters secretKeyParameters = this.params.getSecretKeyParameters();
        IBBEDel07CiphertextParameters ciphertextParameters = this.params.getCiphertextParameters();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());

        int index = 0;
        //test if the user is in the broadcast receiver set
        for (index = 0; index < params.getNumberOfBroadcastReceiver(); index++) {
            if (secretKeyParameters.getId().equals(params.getIdsAt(index))) {
                break;
            }
        }
        //user is not in the broadcast receiver set
        if (index >= params.getNumberOfBroadcastReceiver()) {
            throw new InvalidCipherTextException("User identity is not in the broadcast receiver set, cannot decapsulate...");
        }

        Element[] elementsIdsWithoutTarget = new Element[this.params.getNumberOfBroadcastReceiver() - 1];
        for (int i = 0, j = 0; i < params.getNumberOfBroadcastReceiver(); i++) {
            if (i == index) {
                continue;
            } else {
                elementsIdsWithoutTarget[j] = PairingUtils.MapToZr(pairing, this.params.getIdsAt(i)).getImmutable();
                j++;
            }
        }

        //decapsulation
        Element[] coefficientsForP = HornerRule.ComputeEfficients(pairing, elementsIdsWithoutTarget);
        Element temp1 = pairing.getG2().newOneElement().getImmutable();

        for (int i = 1; i < coefficientsForP.length; i++) {
            temp1 = temp1.mul(publicKeyParameters.getHsAt(i-1).powZn(coefficientsForP[i])).getImmutable();
        }

        Element tempPow = pairing.getZr().newOneElement().getImmutable();
        for (int i = 0; i < elementsIdsWithoutTarget.length; i++) {
            tempPow = tempPow.mulZn(elementsIdsWithoutTarget[i]).getImmutable();
        }
        tempPow = tempPow.invert().getImmutable();

        Element sessionKey = pairing.pairing(ciphertextParameters.getC1(), temp1)
                .mul(pairing.pairing(secretKeyParameters.getSecretKey(), ciphertextParameters.getC2()))
                .powZn(tempPow).getImmutable();
        byte[] byteArraySessionKey = sessionKey.toBytes();
        return Arrays.copyOf(byteArraySessionKey, byteArraySessionKey.length);
    }
}

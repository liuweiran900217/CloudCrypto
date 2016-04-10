package cn.edu.buaa.crypto.encryption.re;

import cn.edu.buaa.crypto.pairingkem.params.PairingCiphertextParameters;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/4/5.
 */
public interface OOREEngine extends REEngine {
    /**
     * Offline Key Encapsulation Algorithm for RE
     * @param publicKey public key
     * @param n number of revocation identity set
     * @return session key / offline ciphertext pair associated with n
     */
    public PairingKeyEncapsulationPair offlineEncapsulation(CipherParameters publicKey, int n);

    /**
     * Online Key Encapsulation Algorithm for RE
     * @param publicKey public key
     * @param ids revocation identity set
     * @return session key / ciphertext pair associated with the revocation identity set
     */
    public PairingKeyEncapsulationPair onlineEncapsulation(CipherParameters publicKey, PairingCiphertextParameters iCiphertext, String... ids);
}

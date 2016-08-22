package cn.edu.buaa.crypto.algebra;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;

/**
 * Created by Weiran Liu on 2016/8/22.
 *
 * Given efficients of n fundamental polynomials, computes the efficients of the extended n-degree polynomial.
 *
 * The algorithm is called Horner's Rule, or Qin Jiu Zhao algorithm.
 * The detailed algorithm is shown in the paper:
 * Nigel P. Smart, Frederik Vercauteren. Fully Homomorphic Encryption with Relatively Small Key and Ciphertext Sizes.
 * PKC 2010, pp. 420 - 443, 2010.
 *
 * @author Hanwen Feng <A HREF="mailto:feng_hanwen@buaa.edu.cn"> (feng_hanwen@buaa.edu.cn) </A> and
 * Weiran Liu
 */
public class HornerRule {
    /**
     * Compute n efficients for n-degree polynomials by given n elementary efficients
     * @param elementaryEfficient
     * @return n efficients
     */
    public static Element[] ComputeEfficients(Pairing pairing, Element[] elementaryEfficient) {
        int n = elementaryEfficient.length;
        Element[] allEfficients = new Element[n+1];
        //set a_{n} to be 1
        allEfficients[n] = pairing.getZr().newOneElement().getImmutable();
        //set all other efficients to be initially zero
        for (int i = 0; i < n; i++) {
            allEfficients[i] = pairing.getZr().newZeroElement().getImmutable();
        }
        for (int k = 0; k < n; k++) {
            for (int i = n - k - 1; i < n - 1; i++) {
                allEfficients[i] = allEfficients[i].add(allEfficients[i + 1].mulZn(elementaryEfficient[k])).getImmutable();
            }
            allEfficients[n-1] = allEfficients[n-1].add(elementaryEfficient[k]).getImmutable();
        }
        return allEfficients;
    }
}

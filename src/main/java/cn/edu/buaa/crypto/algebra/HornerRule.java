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
 * Given coefficients of n fundamental polynomials, computes the coefficients of the extended n-degree polynomial.
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
     * Compute n coefficients for n-degree polynomials by given n elementary coefficients
     * @param elementaryCoefficient
     * @return n coefficients
     */
    public static Element[] ComputeEfficients(Pairing pairing, Element[] elementaryCoefficient) {
        int n = elementaryCoefficient.length;
        Element[] allCoefficients = new Element[n+1];
        //set a_{n} to be 1
        allCoefficients[n] = pairing.getZr().newOneElement().getImmutable();
        //set all other efficients to be initially zero
        for (int i = 0; i < n; i++) {
            allCoefficients[i] = pairing.getZr().newZeroElement().getImmutable();
        }
        for (int k = 0; k < n; k++) {
            for (int i = n - k - 1; i < n - 1; i++) {
                allCoefficients[i] = allCoefficients[i].add(allCoefficients[i + 1].mulZn(elementaryCoefficient[k])).getImmutable();
            }
            allCoefficients[n-1] = allCoefficients[n-1].add(elementaryCoefficient[k]).getImmutable();
        }
        return allCoefficients;
    }
}

package com.example.lsss.lcw10;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.lsss.lcw10.LSSSLCW10Engine;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

/**
 * Created by Weiran Liu on 2016/7/18.
 */
public class LSSSLCW10EngineTest {
    public static void main(String[] args) {
        //generate pairing parameters
        TypeACurveGenerator pg = new TypeACurveGenerator(320, 512);
        PairingParameters typeAParams = pg.generate();
        Pairing pairing = PairingFactory.getPairing(typeAParams);
        int accessPolicy[][] = {
                {10, 10, -1, -2, -3, -4, -5, -6, -7, -8, -9,-10,
//                        -11,-12,-13,-14,-15,-16,-17,-18,-19,-20,
//                        -21,-22,-23,-24,-25,-26,-27,-28,-29,-30,
//                        -31,-32,-33,-34,-35,-36,-37,-38,-39,-40,
//                        -41,-42,-43,-44,-45,-46,-47,-48,-49,-50,
                }};
        AccessControlEngine lsssPolicyEngine = LSSSLCW10Engine.getInstance();
        String[] rhos = new String[] {
                "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
//                "10","11","12","13","14","15","16","17","18","19",
//                "20","21","22","23","24","25","26","27","28","29",
//                "30","31","32","33","34","35","36","37","38","39",
//                "40","41","42","43","44","45","46","47","48","49",
        };

        try {
            //test LSSS Matrix generation algorithm
            AccessControlParameter lsssPolicyParameter = lsssPolicyEngine.generateAccessControl(accessPolicy, rhos);
            System.out.println(lsssPolicyParameter);
            //SecretSharing
            Element secret = pairing.getZr().newRandomElement().getImmutable();
            System.out.println("Secret s = " + secret);
            Element[] lambda = lsssPolicyEngine.secretSharing(pairing, secret, lsssPolicyParameter);
            String[] attributeSet = new String[] {
                    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
//                    "10","11","12","13","14","15","16","17","18","19",
//                    "20","21","22","23","24","25","26","27","28","29",
//                    "30","31","32","33","34","35","36","37","38","39",
//                    "40","41","42","43","44","45","46","47","48","49",
            };
            Element[] elementResult = lsssPolicyEngine.reconstructOmegas(pairing, attributeSet, lsssPolicyParameter);
            Element reconstructedSecret = pairing.getZr().newZeroElement().getImmutable();
            for (int i = 0; i < elementResult.length; i++) {
                reconstructedSecret = reconstructedSecret.add(lambda[i].mulZn(elementResult[i])).getImmutable();
            }
            System.out.println(reconstructedSecret);
        } catch (UnsatisfiedAccessControlException e) {
            e.printStackTrace();
        }
    }
}

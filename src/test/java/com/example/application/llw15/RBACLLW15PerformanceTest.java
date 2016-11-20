package com.example.application.llw15;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.application.llw15.RBACLLW15Engine;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.utils.Timer;
import edu.princeton.cs.algs4.Out;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/10/8.
 *
 * Liu-Liu-Wu EHR role-based access control scheme performance test
 */
public class RBACLLW15PerformanceTest {
    //file path for performance test result
    private static final String path = "benchmarks/application/LLW15/" + RBACLLW15Engine.SCHEME_NAME + ".txt";
    //the test round is chosen according to the full version of our paper.
    private static final int test_round = 100;
    //the maximal depth of roles is chosen according to the full version of our paper.
    private static final int maximal_depth = 10;
    //the maximal number of role index is chosen
    private static final int maximal_roles = 100;

    //setup time
    private double timeSetep;

    //patient identity
    private static final String patientId = "Patient";
    //patient access credential generation time
    private double timeAccessCredentialGenP;
    //patient access credential generation time using intermediate parameters
    private double timeAccessCredentialGenPWithIntermediate;

    //time
    private static final String timeT = "2016.06";
    //medical staff role vectors
    private String[][] medicalStaffRoleVectors = new String[maximal_depth][maximal_roles];
    //medical staff access credential generation time
    private double[] timeAccessCredentialGenM = new double[maximal_depth];
    //medical staff access credential generation time using intermediate parameters
    private double[] timeAccessCredentialGenMWithIntermediate = new double[maximal_depth];

    //medical staff access credential delegation time
    private double[] timeAccessCredentialDeleM = new double[maximal_depth];
    //medical staff access credential delegation time using intermediate parameters
    private double[] timeAccessCredentialDeleMWithIntermediate = new double[maximal_depth];

    //role vectors for key encapsulation
    private String[][] encapsulationRoleVectorSets = new String[maximal_roles][maximal_roles];
    //EHR key encapsulation time
    private double[] timeEHREncapsulation = new double[maximal_roles];
    //EHR key encapsulation time using intermediate parameters
    private double[] timeEHREncapsulationWithIntermediate = new double[maximal_roles];

    //EHR audit time
    private double[] timeEHRAudit = new double[maximal_roles];

    //patient EHR decapsulation time
    private double[] timeEHRDecapsulationP = new double[maximal_roles];

    //medical staff EHR decapsulation time
    private double[][] timeEHRDecapsulationM = new double[maximal_depth][maximal_roles];

    private RBACLLW15Engine engine;
    private PairingParameters pairingParameters;

    private Out out;

    private RBACLLW15PerformanceTest(PairingParameters pairingParameters, RBACLLW15Engine engine) {
        this.engine = engine;
        this.pairingParameters = pairingParameters;
        out = new Out(path);

        //create role vectors for medical staff
        for (int i = 0; i < maximal_depth; i++){
            for (int j = 0; j <= i; j++){
                this.medicalStaffRoleVectors[i][j] = "Role_" + (j);
            }
        }
//        for (int i = 0; i < this.medicalStaffRoleVectors.length; i++) {
//            out.print("i = " + i + ": ");
//            for (int j = 0; j < this.medicalStaffRoleVectors[i].length; j++) {
//                out.print(this.medicalStaffRoleVectors[i][j] + " ");
//            }
//            out.println();
//        }

        //create role vectors for key encapsulation
        for (int i = 0; i < maximal_roles; i++){
            for (int j = 0; j <= i; j++){
                this.encapsulationRoleVectorSets[i][j] = "Role_" + (j);
            }
        }
//        for (int i = 0; i < this.encapsulationRoleVectorSets.length; i++) {
//            out.print("i = " + i + ": ");
//            for (int j = 0; j < this.encapsulationRoleVectorSets[i].length; j++) {
//                out.print(this.encapsulationRoleVectorSets[i][j] + " ");
//            }
//            out.println();
//        }
    }

    private void performanceTest() {
        for (int i = 0; i < test_round; i++) {
            System.out.println("Test round: " + (i+1));
            out.println("Test round: " + (i+1));
            test_one_round();
        }
        //write results to the file
        //write setup time
        out.print("Setup : ");
        out.print("\t" + this.timeSetep / test_round);
        out.println();

        //write ACGenP time
        out.print("ACGenP: ");
        out.print("\t" + this.timeAccessCredentialGenP / test_round);
        out.println();

        //write ACGenP with pre-compute
        out.print("FACGenP: ");
        out.print("\t" + this.timeAccessCredentialGenPWithIntermediate / test_round);
        out.println();

        //write ACGenM
        out.print("ACGenM: ");
        for (int i = 0; i < maximal_depth; i++) {
            out.print("\t" + this.timeAccessCredentialGenM[i] / test_round);
        }
        out.println();

        //write ACGenM with pre-compute
        out.print("FACGenM: ");
        for (int i = 0; i < maximal_depth; i++) {
            out.print("\t" + this.timeAccessCredentialGenMWithIntermediate[i] / test_round);
        }
        out.println();

        //write ACDeleM
        out.print("ACDeleM: ");
        for (int i = 0; i < maximal_depth - 1; i++) {
            out.print("\t" + this.timeAccessCredentialDeleM[i + 1] / test_round);
        }
        out.println();

        //write ACDeleM with pre-compute
        out.print("FACDeleM: ");
        for (int i = 0; i < maximal_depth - 1; i++) {
            out.print("\t" + this.timeAccessCredentialDeleMWithIntermediate[i + 1] / test_round);
        }
        out.println();

        //write EHR encapsulation
        out.print("EHREnc: ");
        for (int i = 0; i < maximal_roles; i++) {
            out.print("\t" + this.timeEHREncapsulation[i] / test_round);
        }
        out.println();

        //write EHR encapsulation with pre-compute
        out.print("FEHREnc: ");
        for (int i = 0; i < maximal_roles; i++) {
            out.print("\t" + this.timeEHREncapsulationWithIntermediate[i] / test_round);
        }
        out.println();

        //write EHR audit
        out.print("EHRAudit: ");
        for (int i = 0; i < maximal_roles; i++) {
            out.print("\t" + this.timeEHRAudit[i] / test_round);
        }
        out.println();

        //write EHRDecP
        out.print("EHRDecP: ");
        //test patient decapsulation performance
        for (int i = 0; i < maximal_roles; i++) {
            out.print("\t" + this.timeEHRDecapsulationP[i] / test_round);
        }
        out.println();

        //write EHRDecM
        for (int i = 0; i < maximal_depth; i++) {
            out.print("EHRDecM " + i + ": ");
            for (int j = i; j < maximal_roles; j++) {
                out.print("\t" + this.timeEHRDecapsulationM[i][j] / test_round);
            }
            out.println();
        }
        out.println();
    }

    private void test_one_round() {
        double temperTime;
        Timer timer = new Timer(maximal_roles);
        //test setup performance
        System.out.print("Setup; ");
        out.print("Setup : ");
        timer.start(0);
        PairingKeySerPair keyPair = engine.Setup(pairingParameters, maximal_roles);
        temperTime = timer.stop(0);
        out.print("\t" + temperTime);
        this.timeSetep += temperTime;
        out.println();

        PairingKeySerParameter publicKey = keyPair.getPublic();
        PairingKeySerParameter masterKey = keyPair.getPrivate();

        System.out.print("ACGenP; ");
        out.print("ACGenP: ");
        //test patient access credential Generation performance
        timer.start(0);
        PairingKeySerParameter accessCredentialPatient = engine.ACGenP(publicKey, masterKey, patientId);
        temperTime = timer.stop(0);
        out.print("\t" + temperTime);
        this.timeAccessCredentialGenP += temperTime;
        out.println();

        System.out.print("FACGenP; ");
        out.print("FACGenP: ");
        PairingCipherSerParameter intermediateParametersAccessCredentialPaitent = engine.IntermediateGen(publicKey);
        timer.start(0);
        accessCredentialPatient = engine.ACGenP(publicKey, masterKey, intermediateParametersAccessCredentialPaitent, patientId);
        temperTime = timer.stop(0);
        out.print("\t" + temperTime);
        this.timeAccessCredentialGenPWithIntermediate += temperTime;
        out.println();

        System.out.print("ACGenM; ");
        out.print("ACGenM: ");
        //test medical staff access credential generation performance
        PairingKeySerParameter[] accessCredentialMedicalStaff = new PairingKeySerParameter[maximal_depth];
        PairingCipherSerParameter[] accessCredentialMedicalStaffIntermediateParameters = new PairingCipherSerParameter[maximal_depth];
        for (int i = 0; i < maximal_depth; i++) {
            timer.start(i);
            accessCredentialMedicalStaff[i] = engine.ACGenM(publicKey, masterKey, medicalStaffRoleVectors[i], timeT);
            temperTime = timer.stop(i);
            out.print("\t" + temperTime);
            this.timeAccessCredentialGenM[i] += temperTime;
        }
        out.println();

        System.out.print("FACGenM; ");
        out.print("FACGenM: ");
        for (int i = 0; i < maximal_depth; i++) {
            accessCredentialMedicalStaffIntermediateParameters[i] = engine.IntermediateGen(publicKey);
            timer.start(i);
            accessCredentialMedicalStaff[i] = engine.ACGenM(publicKey, masterKey, accessCredentialMedicalStaffIntermediateParameters[i],
                    medicalStaffRoleVectors[i], timeT);
            temperTime = timer.stop(i);
            out.print("\t" + temperTime);
            this.timeAccessCredentialGenMWithIntermediate[i] += temperTime;
        }
        out.println();

        System.out.print("ACDeleM; ");
        out.print("ACDeleM: ");
        //test medical staff access credential delegation performance
        PairingKeySerParameter[] accessCredentialDelegateMedicalStaff = new PairingKeySerParameter[maximal_depth];
        PairingCipherSerParameter[] accessCredentialDelegateMedicalStaffIntermediateParameters = new PairingCipherSerParameter[maximal_depth];
        for (int i = 0; i < maximal_depth - 1; i++) {
            timer.start(i + 1);
            accessCredentialDelegateMedicalStaff[i + 1] = engine.ACDeleM(publicKey, accessCredentialMedicalStaff[i], i + 1, "Delegate");
            temperTime = timer.stop(i + 1);
            out.print("\t" + temperTime);
            this.timeAccessCredentialDeleM[i + 1] += temperTime;
        }
        out.println();

        System.out.print("FACDeleM; ");
        out.print("FACDeleM: ");
        for (int i = 0; i < maximal_depth - 1; i++) {
            accessCredentialDelegateMedicalStaffIntermediateParameters[i + 1] = engine.IntermediateGen(publicKey);
            timer.start(i + 1);
            accessCredentialDelegateMedicalStaff[i + 1] = engine.ACDeleM(publicKey, accessCredentialMedicalStaff[i],
                    accessCredentialDelegateMedicalStaffIntermediateParameters[i + 1], i + 1, "Delegate");
            temperTime = timer.stop(i + 1);
            out.print("\t" + temperTime);
            this.timeAccessCredentialDeleMWithIntermediate[i + 1] += temperTime;
        }
        out.println();

        System.out.print("EHREnc; ");
        out.print("EHREnc: ");
        //test key encapsulation performance
        PairingCipherSerParameter[] encapsulations = new PairingCipherSerParameter[maximal_roles];
        PairingCipherSerParameter[] encapsulationsIntermedicateParameters = new PairingCipherSerParameter[maximal_roles];
        for (int i = 0; i < maximal_roles; i++) {
            timer.start(i);
            PairingKeyEncapsulationSerPair encapsulationPair = engine.EHREnc(publicKey, patientId, encapsulationRoleVectorSets[i], timeT);
            encapsulations[i] = encapsulationPair.getCiphertext();
            temperTime = timer.stop(i);
            out.print("\t" + temperTime);
            this.timeEHREncapsulation[i] += temperTime;
        }
        out.println();

        System.out.print("FEHREnc; ");
        out.print("FEHREnc: ");
        for (int i = 0; i < maximal_roles; i++) {
            encapsulationsIntermedicateParameters[i] = engine.IntermediateGen(publicKey);
            timer.start(i);
            PairingKeyEncapsulationSerPair encapsulationPair = engine.EHREnc(publicKey, encapsulationsIntermedicateParameters[i],
                    patientId, encapsulationRoleVectorSets[i], timeT);
            encapsulations[i] = encapsulationPair.getCiphertext();
            temperTime = timer.stop(i);
            out.print("\t" + temperTime);
            this.timeEHREncapsulationWithIntermediate[i] += temperTime;
        }
        out.println();

        System.out.print("EHRAudit; ");
        out.print("EHRAudit: ");
        //test EHR encapsulation audit performance
        for (int i = 0; i < maximal_roles; i++) {
            timer.start(i);
            engine.EHRAudit(publicKey, patientId, encapsulationRoleVectorSets[i], timeT, encapsulations[i]);
            temperTime = timer.stop(i);
            out.print("\t" + temperTime);
            this.timeEHRAudit[i] += temperTime;
        }
        out.println();

        System.out.print("EHRDecP; ");
        out.print("EHRDecP: ");
        //test patient decapsulation performance
        for (int i = 0; i < maximal_roles; i++) {
            try {
                timer.start(i);
                engine.EHRDecP(publicKey, patientId, encapsulationRoleVectorSets[i], timeT, encapsulations[i], accessCredentialPatient);
                temperTime = timer.stop(i);
                out.print("\t" + temperTime);
                this.timeEHRDecapsulationP[i] += temperTime;
            } catch (InvalidCipherTextException e) {
                e.printStackTrace();
                System.exit(0);
            }
        }
        out.println();

        //test medical staff decapsulation performance
        for (int i = 0; i < maximal_depth; i++) {
            System.out.print("EHRDecM " + i + "; ");
            out.print("EHRDecM " + i + ": ");
            for (int j = i; j < maximal_roles; j++) {
                try {
                    timer.start(i);
                    engine.EHRDecM(publicKey, patientId, encapsulationRoleVectorSets[j], timeT, encapsulations[j], accessCredentialMedicalStaff[i]);
                    temperTime = timer.stop(i);
                    out.print("\t" + temperTime);
                    this.timeEHRDecapsulationM[i][j] += temperTime;
                } catch (InvalidCipherTextException e) {
                    e.printStackTrace();
                    System.exit(0);
                }
            }
            out.println();
        }
        out.println();
        System.out.println();
    }

    public static void main(String[] args) {
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a_160_512);
        new RBACLLW15PerformanceTest(pairingParameters, RBACLLW15Engine.getInstance()).performanceTest();
    }
}

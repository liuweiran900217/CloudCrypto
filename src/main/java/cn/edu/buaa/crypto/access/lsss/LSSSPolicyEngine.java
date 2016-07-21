package cn.edu.buaa.crypto.access.lsss;

import Jama.Matrix;
import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/7/21.
 *
 * LSSSPolicyEngine class that implements AccessControlEngine.
 * Since the implementations of function secretSharing, reconstructOmegas are the same in LSSS realization,
 * I create this abstract engine to cover all the same codes.
 */
public abstract class LSSSPolicyEngine implements AccessControlEngine {
    public Map<String, Element> secretSharing(Pairing pairing, Element secret, AccessControlParameter accessControlParameter) throws UnsatisfiedAccessControlException {
        if (!(accessControlParameter instanceof LSSSPolicyParameter)) {
            throw new UnsatisfiedAccessControlException("Invalid LSSSPolicy Parameter, find " + accessControlParameter.getClass().getName());
        }
        LSSSPolicyParameter lsssPolicyParameter = (LSSSPolicyParameter)accessControlParameter;
        int row = lsssPolicyParameter.getRow();
        int column = lsssPolicyParameter.getColumn();
        int[][] lsssMatrix = lsssPolicyParameter.getLSSSMatrix();
        Element[][] elementLSSSMatrix = new Element[row][column];
        for (int i = 0; i < lsssPolicyParameter.getRow(); i++) {
            for (int j = 0; j < lsssPolicyParameter.getColumn(); j++) {
                elementLSSSMatrix[i][j] = pairing.getZr().newElement(lsssMatrix[i][j]).getImmutable();
            }
        }
        //init vector v
        Element[] elementsV = new Element[column];
        elementsV[0] = secret.duplicate().getImmutable();
        for (int i = 1; i < elementsV.length; i++) {
            elementsV[i] = pairing.getZr().newRandomElement().getImmutable();
        }
        //secret share by matrix multiplication
        Map<String, Element> lambdaElementsMap = new HashMap<String, Element>();
        for (int i=0; i<row; i++) {
            Element elementsLambda = pairing.getZr().newZeroElement().getImmutable();
            for (int j=0; j<column; j++) {
                elementsLambda = elementsLambda.add(elementLSSSMatrix[i][j].mulZn(elementsV[j])).getImmutable();
            }
            lambdaElementsMap.put(lsssPolicyParameter.getRhos()[i], elementsLambda);
        }
        return lambdaElementsMap;
    }

    public Map<String, Element> reconstructOmegas(Pairing pairing, String[] attributes, AccessControlParameter accessControlParameter) throws UnsatisfiedAccessControlException {
        if (!(accessControlParameter instanceof LSSSPolicyParameter)) {
            throw new UnsatisfiedAccessControlException("Invalid LSSSPolicy Parameter, find " + accessControlParameter.getClass().getName());
        }
        LSSSPolicyParameter lsssPolicyParameter = (LSSSPolicyParameter)accessControlParameter;
        int[] result;
        String[] minSatisfiedAttributes = lsssPolicyParameter.minSatisfiedAttributeSet(attributes);
        String[] leafAttributes = lsssPolicyParameter.getRhos();
        int[] rows = new int[minSatisfiedAttributes.length];
        int counter = 0;
        for(int i = 0; i < leafAttributes.length; i++){
            for(int j = 0; j < minSatisfiedAttributes.length; j++){
                if(leafAttributes[i].equals(minSatisfiedAttributes[j])) {
                    //比较L矩阵和获得的S参数中各个元素，记下所有相同的元素对应的在数组中的位置，并生成一个新的矩阵，把相同的元素存在一个叫做result的数组之中，长度为counter
                    rows[counter++] = i;
                }
            }
        }
        result = new int[counter];
        System.arraycopy(rows, 0, result, 0, counter);
        //filter M to rows from all zero cols and transpose it
        //eliminate all zero cols
        counter = 0;
        int [] cols = new int[result.length];
        for(int j = 0; j < lsssPolicyParameter.getColumn(); j++){
            for(int i = 0; i < result.length; i++){
                if(lsssPolicyParameter.getLSSSMatrix()[result[i]][j] != 0) {
                    if(counter == cols.length){
                        //此时矩阵不满足解密的条件
                        throw new UnsatisfiedAccessControlException("Invalid access structure or attributes. Unable to reconstruct coefficients.");
                    }
                    //把不都为0的列数调出来，把列数j存到叫做的cols的数组之中,此时counter的含义是代表了新生成的M矩阵的列数
                    cols[counter++] = j;
                    break;
                }
            }
        }
        double[][] Mreduced = new double[counter][counter];
        for(int i = 0; i < result.length; i++){
            for(int j = 0; j < result.length; j++){
                //将原本M矩阵中的满足attributes条件的以及不都为0的列的条件的元素填到一个新的矩阵中，称为Mreduced，该矩阵事宜个长宽均为result.length的方阵
                Mreduced[j][i] = lsssPolicyParameter.getLSSSMatrix()[result[j]][cols[i]];
            }
        }
        //solve the linear system
        Matrix mA = new Matrix(Mreduced);
        mA = mA.inverse();
        double[] _b = get_identity_vector(mA.getColumnDimension());
        Matrix mb = new Matrix(_b, 1);
        Matrix res = mb.times(mA);
        double[] solution = res.getRowPackedCopy();

        Element[] minSatisfiedOmegaElements = new Element[solution.length];
        for (int i = 0; i < minSatisfiedOmegaElements.length; i++) {
            minSatisfiedOmegaElements[i] = pairing.getZr().newElement(pairing.getZr().newElement((int) solution[i])).getImmutable();
        }

        Map<String, Element> omegaElementsMap = new HashMap<String, Element>();
        for (int i = 0; i < rows.length; i++) {
            for (int j = 0; j < attributes.length; j++) {
                if (leafAttributes[rows[i]].equals(attributes[j])) {
                    omegaElementsMap.put(attributes[j], minSatisfiedOmegaElements[i].duplicate().getImmutable());
                }
            }
        }
        for (int i = 0; i < attributes.length; i++) {
            if (!omegaElementsMap.containsKey(attributes[i])) {
                omegaElementsMap.put(attributes[i], pairing.getZr().newZeroElement().getImmutable());
            }
        }
        return omegaElementsMap;
    }

    private double[] get_identity_vector(int length) {
        ;//该方法实现的功能是：生成矩阵求逆时等号右边的列向量，第一个数为1，剩下的都是0
        double[] result = new double[length];
        result[0] = 1.0;
        for(int i = 1; i < length; i++) {
            result[i] = 0.0;
        }
        return result;
    }
}

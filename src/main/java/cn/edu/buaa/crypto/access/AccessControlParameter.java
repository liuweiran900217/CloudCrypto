package cn.edu.buaa.crypto.access;

/**
 * Created by Weiran Liu on 2016/7/19.
 */
public class AccessControlParameter {
    //The Access Tree
    protected AccessTreeNode rootAccessTreeNode;
    //Rho map
    protected String[] rhos;

    public AccessControlParameter(AccessTreeNode accessTreeNode, String[] rhos) {
        this.rootAccessTreeNode = accessTreeNode;
        //Copy rhos
        this.rhos = new String[rhos.length];
        System.arraycopy(rhos, 0, this.rhos, 0, rhos.length);
    }

    public String[] getRhos() {
        return this.rhos;
    }

    public String[] minSatisfiedAttributeSet(String[] attributes) throws UnsatisfiedAccessControlException {
        if (!this.rootAccessTreeNode.isAccessControlSatisfied(attributes)) {
            throw new UnsatisfiedAccessControlException("Give attribute set does not satisfy access policy");
        }
        boolean[] isRedundantAttribute = new boolean[attributes.length];
        int numOfMinAttributeSet = attributes.length;
        for (int i = 0; i < isRedundantAttribute.length; i++) {
            isRedundantAttribute[i] = true;
            numOfMinAttributeSet--;
            String[] minAttributeSet = new String[numOfMinAttributeSet];
            for (int j = 0, k = 0; j < attributes.length; j++) {
                if (isRedundantAttribute[j]) {
                    continue;
                } else {
                    minAttributeSet[k] = attributes[j];
                    k++;
                }
            }
            if (!this.rootAccessTreeNode.isAccessControlSatisfied(minAttributeSet)) {
                numOfMinAttributeSet++;
                isRedundantAttribute[i] = false;
            }
        }
        String[] minAttributeSet = new String[numOfMinAttributeSet];
        for (int j = 0, k = 0; j < attributes.length; j++) {
            if (isRedundantAttribute[j]) {
                continue;
            } else {
                minAttributeSet[k] = attributes[j];
                k++;
            }
        }
        return minAttributeSet;
    }

    public AccessTreeNode getRootAccessTreeNode() {
        return this.rootAccessTreeNode;
    }
}

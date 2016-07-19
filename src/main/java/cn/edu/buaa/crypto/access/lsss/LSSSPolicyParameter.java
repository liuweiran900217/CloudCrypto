package cn.edu.buaa.crypto.access.lsss;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.AccessTreeNode;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;

/**
 * Created by Weiran Liu on 2016/7/18.
 */
public class LSSSPolicyParameter extends AccessControlParameter {
    //The LSSS matrix
    private int[][] lsssMatrix;
    //number of rows
    private int row;
    //number of columns
    private int column;

    public LSSSPolicyParameter(AccessTreeNode rootAccessTreeNode, int[][] lsssMatrix, String[] rhos) {
        super(rootAccessTreeNode, rhos);
        this.row = lsssMatrix.length;
        this.column = lsssMatrix[0].length;
        this.lsssMatrix = new int[row][column];
        //Copy LSSS Matrix
        for (int i=0; i<this.row; i++) {
            System.arraycopy(lsssMatrix[i], 0, this.lsssMatrix[i], 0, column);
        }
    }

    public int getRow() {
        return this.row;
    }

    public int getColumn() { return this.column; }

    public int[][] getLSSSMatrix(){
        return this.lsssMatrix;
    }

    public String[] getRhos() {
        return this.rhos;
    }

    @Override
    public String toString(){
        StringBuffer buffer = new StringBuffer("M[][], L[i]\n");
        for(int i=0; i<row; i++){
            buffer.append(i + " |");
            for(int j=0; j<column; j++){
                buffer.append(lsssMatrix[i][j] + ",");
            }
            buffer.append("|, Rho["+i+"] = " + rhos[i]);
            buffer.append("\n");
        }
        return buffer.toString();
    }
}

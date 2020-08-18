package cn.edu.buaa.crypto.access.lsss;

import java.util.HashMap;
import java.util.Map;

import Jama.Matrix;
import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

/**
 * Created by Weiran Liu on 2016/7/21.
 *
 * LSSSPolicyEngine class that implements AccessControlEngine. Since the
 * implementations of function secretSharing, reconstructOmegas are the same in
 * LSSS realization, I create this abstract engine to cover all the same codes.
 */
public abstract class LSSSPolicyEngine implements AccessControlEngine {
	public Map<String, Element> secretSharing(Pairing pairing, Element secret,
			AccessControlParameter accessControlParameter) {
		if (!(accessControlParameter instanceof LSSSPolicyParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(this.getEngineName(), accessControlParameter,
					LSSSPolicyParameter.class.getName());
		}
		LSSSPolicyParameter lsssPolicyParameter = (LSSSPolicyParameter) accessControlParameter;
		int row = lsssPolicyParameter.getRow();
		int column = lsssPolicyParameter.getColumn();
		int[][] lsssMatrix = lsssPolicyParameter.getLSSSMatrix();
		Element[][] elementLSSSMatrix = new Element[row][column];
		for (int i = 0; i < lsssPolicyParameter.getRow(); i++) {
			for (int j = 0; j < lsssPolicyParameter.getColumn(); j++) {
				elementLSSSMatrix[i][j] = pairing.getZr().newElement(lsssMatrix[i][j]).getImmutable();
			}
		}
		// init vector v
		Element[] elementsV = new Element[column];
		elementsV[0] = secret.duplicate().getImmutable();
		for (int i = 1; i < elementsV.length; i++) {
			elementsV[i] = pairing.getZr().newRandomElement().getImmutable();
		}
		// secret share by matrix multiplication
		Map<String, Element> lambdaElementsMap = new HashMap<String, Element>();
		for (int i = 0; i < row; i++) {
			Element elementsLambda = pairing.getZr().newZeroElement().getImmutable();
			for (int j = 0; j < column; j++) {
				elementsLambda = elementsLambda.add(elementLSSSMatrix[i][j].mulZn(elementsV[j])).getImmutable();
			}
			lambdaElementsMap.put(lsssPolicyParameter.getRhos()[i], elementsLambda);
		}
		return lambdaElementsMap;
	}

	public Map<String, Element> reconstructOmegas(Pairing pairing, String[] attributes,
			AccessControlParameter accessControlParameter) throws UnsatisfiedAccessControlException {

		if (!(accessControlParameter instanceof LSSSPolicyParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(this.getEngineName(), accessControlParameter,
					LSSSPolicyParameter.class.getName());
		}

		System.out.print("attributes: ");
		for (int i = 0; i < attributes.length; i++) {
			System.out.print(attributes[i]);
			if (i < attributes.length - 1) {
				System.out.print(", ");
			}
		}
		System.out.println();

		LSSSPolicyParameter lsssPolicyParameter = (LSSSPolicyParameter) accessControlParameter;
		int[] result;
		String[] minSatisfiedAttributes = lsssPolicyParameter.minSatisfiedAttributeSet(attributes);
		String[] leafAttributes = lsssPolicyParameter.getRhos();
		int[] rows = new int[minSatisfiedAttributes.length];
		int counter = 0;
		for (int i = 0; i < leafAttributes.length; i++) {
			for (String minSatisfiedAttribute : minSatisfiedAttributes) {
//				System.out.printf("leafAttributes[%d](%s) =?= minSatisfiedAttribute(%s)\n", i, leafAttributes[i],
//						minSatisfiedAttribute);
				if (leafAttributes[i].equals(minSatisfiedAttribute)) {
					// 比較L矩陣和獲得的S參數中各個元素，記下所有相同的元素對應的在數組中的位置，並生成一個新的矩陣，把相同的元素存在一個叫做result的數組之中，長度為counter
					rows[counter++] = i;
				}
			}
		}

		System.out.println("Reconstruct lsss matrix:");
		int[][] _lsssM = lsssPolicyParameter.getLSSSMatrix();
		for (int i = 0; i < _lsssM.length; i++) {
			for (int j = 0; j < _lsssM[i].length; j++) {
				System.out.printf("%s", _lsssM[i][j]);

				if (j < _lsssM[i].length - 1) {
					System.out.print(" ");
				}
			}
			if (i < _lsssM.length - 1) {
				System.out.println();
			}
		}
		System.out.println();
		System.out.println();
		
		result = new int[counter];
		System.arraycopy(rows, 0, result, 0, counter);
		// filter M to rows from all zero cols and transpose it
		// eliminate all zero cols
		counter = 0;
		int[] cols = new int[result.length];
		for (int j = 0; j < lsssPolicyParameter.getColumn(); j++) {
			for (int aResult : result) {
				if (lsssPolicyParameter.getLSSSMatrix()[aResult][j] != 0) {
					if (counter == cols.length) {
						// 此時矩陣不滿足解密的條件
						throw new UnsatisfiedAccessControlException(
								"Invalid access structure or attributes. Unable to reconstruct coefficients.");
					}
					// 把不都為0的列數調出來，把列數j存到叫做的cols的數組之中,此時counter的含義是代表了新生成的M矩陣的列數
					cols[counter++] = j;
					break;
				}
			}
		}
		double[][] Mreduced = new double[counter][counter];
		for (int i = 0; i < result.length; i++) {
			for (int j = 0; j < result.length; j++) {
				// 將原本M矩陣中的滿足attributes條件的以及不都為0的列的條件的元素填到一個新的矩陣中，稱為Mreduced，該矩陣事宜個長寬均為result.length的方陣
				Mreduced[j][i] = lsssPolicyParameter.getLSSSMatrix()[result[j]][cols[i]];
			}
		}

		int fc = Mreduced.length;
		System.out.print("Mreduced: \n");
		for (int i = 0; i < Mreduced.length; i++) {
			System.out.print("{");

			int sc = Mreduced[i].length;
			for (int j = 0; j < sc; j++) {
				System.out.printf("\"%.0f\"", Mreduced[i][j]);
				if (j < sc - 1) {
					System.out.print(", ");
				}
			}
			System.out.print("}");
			if (i < fc) {
				System.out.println(",");
			}
		}
		System.out.println();

		// solve the linear system
		Matrix mA = new Matrix(Mreduced);
		mA = mA.inverse();
		double[] _b = get_identity_vector(mA.getColumnDimension());
		Matrix mb = new Matrix(_b, 1);
		Matrix res = mb.times(mA);
		double[] solution = res.getRowPackedCopy();

		Element[] minSatisfiedOmegaElements = new Element[solution.length];
		for (int i = 0; i < minSatisfiedOmegaElements.length; i++) {
			minSatisfiedOmegaElements[i] = pairing.getZr().newElement((int) solution[i]).getImmutable();
		}

		Map<String, Element> omegaElementsMap = new HashMap<String, Element>();
		for (int i = 0; i < rows.length; i++) {
			for (String attribute : attributes) {
				if (leafAttributes[rows[i]].equals(attribute)) {
					omegaElementsMap.put(attribute, minSatisfiedOmegaElements[i].duplicate().getImmutable());
				}
			}
		}
		for (String attribute : attributes) {
			if (!omegaElementsMap.containsKey(attribute)) {
				omegaElementsMap.put(attribute, pairing.getZr().newZeroElement().getImmutable());
			}
		}
		for (Map.Entry entry : omegaElementsMap.entrySet()) {
			System.out.println(entry.getKey() + ", " + entry.getValue());
		}
		return omegaElementsMap;
	}

	private double[] get_identity_vector(int length) {
		// 該方法實現的功能是：生成矩陣求逆時等號右邊的列向量，第一個數為1，剩下的都是0
		double[] result = new double[length];
		result[0] = 1.0;
		for (int i = 1; i < length; i++) {
			result[i] = 0.0;
		}
		return result;
	}
}

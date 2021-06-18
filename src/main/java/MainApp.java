

/**
 * 
 */

import supplierintegrations.hackertest.detector.HackerDetectorSingleton;

/**
 * @author Humberto Castellano
 *
 */
public class MainApp {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		HackerDetectorSingleton hackerDetector = HackerDetectorSingleton.getInstance();

		hackerDetector.run();
	}

}

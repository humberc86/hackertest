/**
 * 
 */
package supplierintegrations.hackertest.detector;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.WatchService;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.util.Collection;

import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.ArrayListValuedHashMap;

import supplierintegrations.hackertest.detector.interfaces.IHackerDetector;
/**
 * @author Humberto Castellano
 *
 */
public class HackerDetectorSingleton implements IHackerDetector, Runnable {

	private static MultiValuedMap<String, Long> failureLoginAttemptsData;
	private static final String SIGNIN_SUCCESS = "SIGNIN_SUCCESS";
	private static final String SIGNIN_FAILURE = "SIGNIN_FAILURE";
	
	// Typically, this value would be in a properties file
	private static final String LOG_FILES_DIRECTORY_PATH = System.getProperty("user.home") + "/test-logs";
	private static final String LOGIN_FILE_NAME = "login.log";
	
	private HackerDetectorSingleton() {
		
		failureLoginAttemptsData = new ArrayListValuedHashMap<String,Long>(100);
	}
	
	public static HackerDetectorSingleton getInstance() {
		
		return SingletonHelper.HACKER_DETECTOR_SINGLETON;
	}
	
	@Override
	public void run() {
		
		try (WatchService logFileWatchService = FileSystems.getDefault().newWatchService();
				BufferedReader bufferedReader = new BufferedReader(new FileReader(LOG_FILES_DIRECTORY_PATH + "/" + LOGIN_FILE_NAME))) {
			
			Path logFilePath = Paths.get(LOG_FILES_DIRECTORY_PATH);
			logFilePath.register(logFileWatchService, StandardWatchEventKinds.ENTRY_MODIFY);
			
			// Take it to the last line
		    while (bufferedReader.readLine() != null) { }
		    System.out.println("Last line reached. Waiting for next record...");

			boolean poll = true;
			
			while(poll) {
				
				WatchKey key = logFileWatchService.take();
				
				for(WatchEvent<?> event : key.pollEvents()) {
					
					if(event.kind().equals(StandardWatchEventKinds.ENTRY_MODIFY)) {
						
						System.out.println("Event " + event.kind() + " on File " + event.context() 
							+ ". Suspicious Activity: " + parseLine(bufferedReader.readLine()));
					}
				}
				
				poll = key.reset();
			}
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			
		}  catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public String parseLine(String line) {
		
		if(line==null || line.isEmpty())
			return null;
		
		String[] stringBlocks = line.split(",");
		String ip = stringBlocks[0];
		Long epochTime = new Long(stringBlocks[1]);
		String status = stringBlocks[2];
		
		if(status.equals(SIGNIN_SUCCESS)) {
			
			// Clean this IP's failure in-memory records for saving memory
			
			this.cleanIpFailureAttempts(ip);
			return null;
		}
		
		if(this.isSuspiciousActivity(ip, epochTime))
			return ip;
		else
			return null;
	}
	
	private boolean isSuspiciousActivity(String ip, Long epochTime) {
		
		this.addIpFailureAttempt(ip, epochTime);
		
		// Check IP activity for the last 5 minutes
		
		Collection<Long> failureLoginAttemptsDataCollection = failureLoginAttemptsData.get(ip);
		
		Long[] failureLoginAttemptsTimes = (Long[])failureLoginAttemptsDataCollection.toArray(new Long[failureLoginAttemptsDataCollection.size()]);
		
		int failureAttemptsCount = failureLoginAttemptsTimes.length;
		
		// If more than 5 failed attempts
		if(failureAttemptsCount >= 5) {
			
			Long currentEpochTime = failureLoginAttemptsTimes[failureAttemptsCount - 1];
			
			Long fiveMinutesBackEpochTime = currentEpochTime - (5*60);
			
			Long oldestEpochTime = failureLoginAttemptsTimes[failureAttemptsCount - 5];
			
			// If oldestAttempt is more recent than 5 minutes
			
			if(oldestEpochTime > fiveMinutesBackEpochTime)
				return true;
		}
		
		return false;
	}
	
	private void cleanIpFailureAttempts(String ip) {
		
		failureLoginAttemptsData.remove(ip);
	}
	
	private void addIpFailureAttempt(String ip, Long epochTime) {
		
		failureLoginAttemptsData.put(ip, epochTime);
	}
	
	// Private class SingletonHelper
	
	private static class SingletonHelper {
		
		private static final HackerDetectorSingleton HACKER_DETECTOR_SINGLETON = new HackerDetectorSingleton();
	}
}

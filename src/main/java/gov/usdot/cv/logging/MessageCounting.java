package gov.usdot.cv.logging;

import gov.usdot.cv.common.util.Syslogger;

import java.util.ArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.commons.lang3.time.DurationFormatUtils;
import org.apache.log4j.Logger;

public class MessageCounting {
	
	private static final Logger log = Logger.getLogger(MessageCounting.class);

	private static final String registryName = "Transport";
	private static final Syslogger syslogger = Syslogger.getInstance();
	
	private static final long startTime = System.currentTimeMillis();
	
	private static AtomicInteger currentIndex = new AtomicInteger(-1);
	
	private static ArrayList<MessageCounter> registry = new ArrayList<MessageCounter>();
	
	private static final long reportingIntervalSec = 5*60L;
	private static ScheduledFuture<?> scheduledReport;
	static {
		ScheduledExecutorService scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
		scheduledReport = scheduledExecutorService.scheduleAtFixedRate(
				new Runnable() {
			        public void run() {
			        	report();
			        }
			    }, reportingIntervalSec, reportingIntervalSec, TimeUnit.SECONDS);
	}
	
	public static int register(String counterType) {
		int index = currentIndex.addAndGet(1);
		registry.add(index, new MessageCounter(counterType));
		log.debug(String.format("Registred logging for %s as index %d", counterType, index));
		return index;
	}
	
	public static synchronized void terminate() {
		if ( scheduledReport != null ) {
			scheduledReport.cancel(false);
			scheduledReport = null;
			report(); // there is a small probability that this report will be redundant but it's better than miss out on the final report altogether.
		}
	}
	
	public static void incrementSuccess(int index) {
		MessageCounter messageCounter = registry.get(index);
		messageCounter.incrementSuccess();
	}
	
	public static void incrementTotal(int index) {
		MessageCounter messageCounter = registry.get(index);
		messageCounter.incrementTotal();
	}
	
	public static void report() {
		StringBuilder sb = new StringBuilder();
		
		int successCount = 0;
		int totalCount = 0;
		for( MessageCounter messageCounter : registry ) {
			int sc = messageCounter.getSuccessCount();
			int tc = messageCounter.getTotalCount();
			sb.append(String.format("%s received %d messages, %d successful; ", messageCounter.counterType, tc, sc));
			successCount += sc;
			totalCount += tc;
		}
		if ( totalCount > 0 ) {
			long delta = System.currentTimeMillis() - startTime;
			String deltaString = DurationFormatUtils.formatDuration(delta, "dd'd' HH'h' mm'm' ss.SS's'");
			sb.append(String.format("In %s (%d ms) received total %d messages, %d successful.",  deltaString, delta, totalCount, successCount));
		} else {
			sb = new StringBuilder("Received 0 messages of any type");
		}
		final String reportString = sb.toString();
		syslogger.log(registryName, reportString);
		log.debug(reportString);
	}

}

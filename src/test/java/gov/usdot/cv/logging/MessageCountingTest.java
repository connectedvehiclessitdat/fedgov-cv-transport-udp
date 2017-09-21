package gov.usdot.cv.logging;

import gov.usdot.cv.common.util.UnitTestHelper;

import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

public class MessageCountingTest {

	private static final Logger log = Logger.getLogger(MessageCountingTest.class);
			
	static final private boolean isDebugOutput = false;

	@BeforeClass
	public static void init() {
		UnitTestHelper.initLog4j(isDebugOutput);
	}
	

	@Test
	public void test() throws InterruptedException {
		int typeOneIndex = MessageCounting.register("TypeOne");
		int typeTwoIndex = MessageCounting.register("TypeTwo");
		
		MessageCounting.incrementSuccess(typeTwoIndex);
		MessageCounting.incrementTotal(typeOneIndex);
		MessageCounting.incrementSuccess(typeOneIndex);
		MessageCounting.incrementTotal(typeTwoIndex);
		MessageCounting.incrementSuccess(typeTwoIndex);
		MessageCounting.incrementTotal(typeTwoIndex);
		MessageCounting.incrementTotal(typeTwoIndex);
		MessageCounting.incrementTotal(typeTwoIndex);
		MessageCounting.incrementTotal(typeOneIndex);
		
		Thread.sleep(13*1000);
		
		MessageCounting.incrementSuccess(typeTwoIndex);
		MessageCounting.incrementTotal(typeOneIndex);
		MessageCounting.incrementSuccess(typeOneIndex);
		MessageCounting.incrementTotal(typeTwoIndex);
		Thread.sleep(6*1000);
		MessageCounting.incrementSuccess(typeTwoIndex);
		MessageCounting.incrementTotal(typeTwoIndex);
		MessageCounting.incrementTotal(typeTwoIndex);
		MessageCounting.incrementTotal(typeTwoIndex);
		MessageCounting.incrementTotal(typeOneIndex);
		
		MessageCounting.terminate();
		Thread.sleep(500);
		log.debug("Last message");
		MessageCounting.incrementSuccess(typeOneIndex);
		MessageCounting.incrementTotal(typeTwoIndex);
		MessageCounting.incrementSuccess(typeTwoIndex);
		MessageCounting.incrementTotal(typeTwoIndex);
		MessageCounting.incrementTotal(typeTwoIndex);
		MessageCounting.incrementTotal(typeTwoIndex);
		MessageCounting.incrementTotal(typeOneIndex);
	}

}

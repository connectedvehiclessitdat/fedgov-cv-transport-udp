package gov.usdot.cv.transport;

import gov.usdot.asn1.generated.j2735.semi.SemiDialogID;
import gov.usdot.cv.common.util.UnitTestHelper;

import org.junit.BeforeClass;
import org.junit.Test;

import com.deleidos.rtws.transport.AbstractTransportService;

public class CvMsgTransportServiceTest {

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(false);
	}

	@Test
	public void test() {
		CvMsgTransportService msgTransport = new CvMsgTransportService();
		msgTransport.setMessageType("advSitDatDist");

		msgTransport.execute();
		AbstractTransportService transportSvc;

		try {
			transportSvc = HelperTransports.map.get(SemiDialogID.objDisc);
			if ( transportSvc != null ) {
				transportSvc.SendJMSMessage("test message for input format " + transportSvc.getInputFormat());
			} else {
				System.out.println("Use default transport");
			}
			transportSvc = HelperTransports.map.get(SemiDialogID.advSitDatDist);
			if ( transportSvc != null ) {
				transportSvc.SendJMSMessage("test message for input format " + transportSvc.getInputFormat());
			} else {
				System.out.println("Use default transport");
			}
		} catch(NullPointerException ex ) {
			System.out.println("JSM exception");
		}
		msgTransport.terminate();
	}

}

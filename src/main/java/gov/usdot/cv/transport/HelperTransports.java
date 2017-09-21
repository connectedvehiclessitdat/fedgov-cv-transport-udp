package gov.usdot.cv.transport;

import com.deleidos.rtws.transport.AbstractTransportService;
import java.util.concurrent.ConcurrentHashMap;
import gov.usdot.asn1.generated.j2735.semi.SemiDialogID;

public class HelperTransports {
	
	static final ConcurrentHashMap<SemiDialogID, AbstractTransportService> map = new ConcurrentHashMap<SemiDialogID, AbstractTransportService>(16, 0.9f, 1);

}

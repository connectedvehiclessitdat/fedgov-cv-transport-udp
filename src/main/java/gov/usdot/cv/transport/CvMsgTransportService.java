package gov.usdot.cv.transport;

import gov.usdot.asn1.generated.j2735.semi.SemiDialogID;
import gov.usdot.cv.common.asn1.DialogIDHelper;

import org.apache.log4j.Logger;

import com.deleidos.rtws.core.framework.Description;
import com.deleidos.rtws.core.framework.UserConfigured;
import com.deleidos.rtws.transport.AbstractTransportService;

@Description("Helper transport that is used to register a message type for an input format")
public class CvMsgTransportService extends AbstractTransportService {
	
	private static final Logger log = Logger.getLogger(CvMsgTransportService.class);
	
	final private String FAKE_RECORD_FORMAT = "BER_ASN-1";
	final private String REAL_RECORD_FORMAT = "NULL";
	final private int RECORD_HEADER_LINES = 0;
	
	private static final String MSG_TYPES = "^(vehSitData|dataSubscription|advSitDataDep|advSitDatDist|objReg|objDisc|intersectionSitDataDep|intersectionSitDataQuery)$";
	
	private SemiDialogID dialogID = SemiDialogID.dataSubscription;
	private String dialogIdName = "dataSubscription";

	public void execute() {	
		super.setRecordFormat(REAL_RECORD_FORMAT);
		super.setRecordHeaderLines(RECORD_HEADER_LINES);
		log.info(String.format("Registered message type '%s' for input format '%s'", dialogIdName, getInputFormat()));
		HelperTransports.map.put(dialogID, this);
	}

	public void terminate() {
		HelperTransports.map.remove(dialogID, this);
		log.info(String.format("Unregistered message type '%s' for input format '%s'", dialogIdName, getInputFormat()));
	}
	
	public String getMessageType() {
		return dialogIdName;
	}

	@UserConfigured(value= "dataSubscription",
			flexValidator = { "RegExpValidator expression=" + MSG_TYPES },
		    description="Specifies message type (i.e. dialog ID) to be processed by this helper transport.")
	public void setMessageType(String messageType) {
		SemiDialogID dlgID = DialogIDHelper.getDialogID(messageType);
		if ( dlgID != null ) {
			dialogIdName = messageType;
			dialogID = dlgID;
		}
	}
	
	@Override
	@UserConfigured(value = FAKE_RECORD_FORMAT,
			flexValidator = { "RegExpValidator expression=" + "^(" + FAKE_RECORD_FORMAT + ")$" },
			description = FAKE_RECORD_FORMAT + " (read only)", convertToSystemConfigured="true")	
	public void setRecordFormat(String recordFormat) {
	}

	@Override
	@UserConfigured(value = RECORD_HEADER_LINES+"",
			flexValidator = { "RegExpValidator expression=" + "^([" + RECORD_HEADER_LINES + "])$" },
			description = "Not applicable (read only)", convertToSystemConfigured="true")			
	public void setRecordHeaderLines(int recordHeaderLines) {
	}
	
	@UserConfigured(value = "1000")
	public void setMaxTimeBetweenFlush(int value) {
		bundler.setFlushInterval(value);
	}
	
	@UserConfigured(value = "true")
	public void setLowVolumeFlushStrategy(boolean lowVolumeFlushStrategy) {
		bundler.setLowVolumeFlushStrategy(lowVolumeFlushStrategy);
	}

}

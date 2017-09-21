package gov.usdot.cv.transport;

import gov.usdot.cv.common.dialog.ReceiptReceiverException;
import gov.usdot.cv.logging.MessageCounting;
import gov.usdot.cv.security.DatabaseCertificateStore;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.session.SessionReceiptReceiver;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

import com.deleidos.rtws.core.framework.Description;
import com.deleidos.rtws.core.framework.UserConfigured;
import com.deleidos.rtws.transport.Services.UDPTransportService;

@Description("Transports connected vehicle UDP packets sent to a configured port")
public class CvUDPTransportService extends UDPTransportService {
	
	private static final Logger log = Logger.getLogger(CvUDPTransportService.class);
	
	public static final int loggerIndex = MessageCounting.register(CvUDPTransportService.class.getSimpleName());
	
	private static boolean isSecurityInitialized = false;

	final private String MESSAGE_PROCESSOR_CLASS = "gov.usdot.cv.transport.UDPMessageProcessor";
	final private String REGEX_MESSAGE_PROCESSOR_CLASS = "gov[.]usdot[.]cv[.]transport[.]UDPMessageProcessor";
	
	final private String FAKE_CONTENT_ENCODING = "DSRC_J2735";
	final private String REAL_CONTENT_ENCODING = "NONE";

	final private String FAKE_RECORD_FORMAT = "BER_ASN-1";
	final private String REAL_RECORD_FORMAT = "NULL";
	
	final public  String MESSAGE_FORMAT_DEFAULT = "IEEE1609Dot2";
	final private String MESSAGE_FORMAT_REGEX   = "^(" + MESSAGE_FORMAT_DEFAULT + "|DSRCJ2735)$";
	
	final private int DEFAULT_FORWARDER_PORT = 46761;
	final private String DEFAULT_RECEIPTS_TOPIC = "cv.receipts";
	
	final private int RECORD_HEADER_LINES = 0;
	
	double nwLat = ServiceRegion.DEFALUT_NW_CNR_LATITUDE, 
		   nwLon = ServiceRegion.DEFALUT_NW_CNR_LONGITUDE, 
		   seLat = ServiceRegion.DEFALUT_SE_CNR_LATITUDE, 
		   seLon = ServiceRegion.DEFALUT_SE_CNR_LONGITUDE;
	
	private String messageFormat = MESSAGE_FORMAT_DEFAULT;

	private String forwarderHostName = "23.253.150.136";
	private int forwarderPort = DEFAULT_FORWARDER_PORT;
	private InetAddress forwarderInetAddress = null;
	private Boolean forwardingRequested = false; // false - redirect not requested, true - redirect requested, null - redirect requested but can not be fulfilled

	private String receiptsTopic = DEFAULT_RECEIPTS_TOPIC;
	
	//
	// Service Region
	//

	private ServiceRegion serviceRegion = new ServiceRegion();
	
	public final ServiceRegion getServiceRegion() {
		return serviceRegion;
	}
	
	private void initServiceRegion() {
		serviceRegion = new ServiceRegion(getSvcNorthwestLatitude(),  getSvcNorthwestLongitude(), getSvcSoutheastLatitude(), getSvcSoutheastLongitude());
	}
	
	private void initReadOnlyParameters() {
		super.setContentEncoding(REAL_CONTENT_ENCODING);
		super.setRecordFormat(REAL_RECORD_FORMAT);
		super.setRecordHeaderLines(RECORD_HEADER_LINES);
		super.setMessageProcessorClass(MESSAGE_PROCESSOR_CLASS);
	}
	
	private void initForwardingSettings() {
		if ( !StringUtils.isBlank(forwarderHostName) ) {
			try {
				forwarderInetAddress = InetAddress.getByName(forwarderHostName);
				forwardingRequested = true;	// forwarding requested
			} catch (UnknownHostException ex) {
				log.error(String.format("Outbound IPv6/IPv4 messages will not be forwarded because forwatder hostname/IP provided cannot be resolved. Reason: %s", ex.getMessage()));
				forwardingRequested = null;	// forwarding requested but can not be fulfilled
			}
		}
	}
	
	private synchronized void initSecurity() throws Exception {
		if ( !isSecurityInitialized ) {
			CryptoProvider.initialize();
			DatabaseCertificateStore.initialize();
			isSecurityInitialized = true;
		}
	}
	
	private synchronized void disposeSecurity() {
		if ( !isSecurityInitialized ) {
			DatabaseCertificateStore.dispose();
			isSecurityInitialized = false;
		}
	}
	
	@Override
	public void execute() {
		try {
			initSecurity();
		} catch (Exception ex) {
			log.error("Couldn't initialize Security", ex);
		}
		initServiceRegion();
		initReadOnlyParameters();
		initForwardingSettings();
		UDPMessageProcessor.sessionMgr.initialize();
		UDPMessageProcessor.receiptReceiver = new SessionReceiptReceiver(getReceiptsTopic());
		UDPMessageProcessor.receiptReceiver.setSessionMgr(UDPMessageProcessor.sessionMgr);
		UDPMessageProcessor.receiptReceiver.setForwarderAddress(getForwardInetAddress());
		UDPMessageProcessor.receiptReceiver.setForwarderPort(getForwarderPort());
		try {
			UDPMessageProcessor.receiptReceiver.initialize();
		} catch (ReceiptReceiverException ex) {
			log.error("Couldn't initialize Session Receipt Receiver", ex);
		}
		super.execute();
	}
	
	@Override
	public void dispose() {
		UDPMessageProcessor.sessionMgr.dispose();
		if ( UDPMessageProcessor.receiptReceiver != null ) {
			try {
				UDPMessageProcessor.receiptReceiver.dispose();
			} catch (ReceiptReceiverException ex) {
				log.warn("Couldn't dispose Session Receipt Receiver", ex);
				UDPMessageProcessor.receiptReceiver = null;
			}
		}
		disposeSecurity();
		super.dispose();
	}
	
	@Override
	public void terminate() {
		MessageCounting.terminate();
		super.terminate();
	}
	
	public InetAddress getForwardInetAddress() {
		return forwarderInetAddress;
	}

	public Boolean getForwardRequested() {
		return forwardingRequested;
	}

	//
	// Service region parameters
	//

    @UserConfigured(value = ServiceRegion.DEFALUT_NW_CNR_LATITUDE+"", description = "The northwest latitude of the service region.", 
            flexValidator = { "NumberValidator minValue=-90.0 maxValue=90.0" })
	public void setSvcNorthwestLatitude(double nwLat) {
	      this.nwLat = nwLat;
	}

	public double getSvcNorthwestLatitude() {
	      return this.nwLat;
	}

	@UserConfigured(value = ServiceRegion.DEFALUT_NW_CNR_LONGITUDE+"", description = "The northwest longitude of the service region.", 
	            flexValidator = { "NumberValidator minValue=-180.0 maxValue=180.0" })
	public void setSvcNorthwestLongitude(double nwLon) {
	      this.nwLon = nwLon;
	}

	public double getSvcNorthwestLongitude() {
	      return this.nwLon;
	}
	
	@UserConfigured(value = ServiceRegion.DEFALUT_SE_CNR_LATITUDE+"", description = "The southeast latitude of the service region.", 
	            flexValidator = { "NumberValidator minValue=-90.0 maxValue=90.0" })
	public void setSvcSoutheastLatitude(double seLat) {
	      this.seLat = seLat;
	}
	
	public double getSvcSoutheastLatitude() {
	      return this.seLat;
	}
	
	@UserConfigured(value = ServiceRegion.DEFALUT_SE_CNR_LONGITUDE+"", description = "The southeast longitude of the service region.", 
	            flexValidator = { "NumberValidator minValue=-180.0 maxValue=180.0" })
	public void setSvcSoutheastLongitude(double seLon) {
	      this.seLon = seLon;
	}
	
	public double getSvcSoutheastLongitude() {
	      return this.seLon;
	}
	
	public String getMessageFormat() {
		return messageFormat;
	}

	@UserConfigured(value=MESSAGE_FORMAT_DEFAULT,
			flexValidator = { "RegExpValidator expression=" + MESSAGE_FORMAT_REGEX },
		    description="Specifies expected incoming message format.")
	public void setMessageFormat(String messageFormat) {
		this.messageFormat = messageFormat;
	}
	
	//
	// IPv6/IPv4 packet forwarder
	// 

	@UserConfigured(value="",
		    description="IP address or host name of IPv6/IPv4 forwarder that is used for incoming traffic (if any)")
	public void setForwarderHostName(String forwarderHostName) {
		this.forwarderHostName = forwarderHostName;
	}
	
	public String getForwarderHostName() {
		return forwarderHostName;
	}
	
	@UserConfigured(value = "" + DEFAULT_FORWARDER_PORT, description = "IP port number to which send packets for forwardering", flexValidator = "NumberValidator minValue=0 maxValue=65535")
	public void setForwarderPort(int forwarderPort) {
		this.forwarderPort = forwarderPort;
	}
	
	public int getForwarderPort() {
		return forwarderPort;
	}
	
	//
	// Receipts Topic
	//
	
	@UserConfigured(
		value = DEFAULT_RECEIPTS_TOPIC,
		description = "The external jms topic to receive receipt.",
		flexValidator = {"StringValidator minLength=2 maxLength=1024"})
	public void setReceiptsTopic(String receiptsTopic) {
		this.receiptsTopic = receiptsTopic;
	}
	
	public String getReceiptsTopic() {
		return this.receiptsTopic;
	}

	//
	// Enforce CV specific message processor
	// 
	
	@Override
	public String getMessageProcessorClass() {
		return MESSAGE_PROCESSOR_CLASS;
	}
		
	@Override
	@UserConfigured(value=MESSAGE_PROCESSOR_CLASS,
	flexValidator = { "RegExpValidator expression=" + "^(" + REGEX_MESSAGE_PROCESSOR_CLASS + ")$ noMatchError=\"Please provide a valid java class name.\"" },
    description="Name of the java class that will be used to process received datagram packets (read only)", convertToSystemConfigured="true")
	public void setMessageProcessorClass(String messageProcessorClass) {
	}
	
	//
	// Modify these inherited read-only parameters
	//
	
	@Override
	@UserConfigured(value=FAKE_CONTENT_ENCODING,
			flexValidator = { "RegExpValidator expression=" + "^(" + FAKE_CONTENT_ENCODING + ")$" },
		    description="Payload encoding standard (read-only)", convertToSystemConfigured="true" )
	public void setContentEncoding(String contentEncoding) {
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
package gov.usdot.cv.transport;

import gov.usdot.asn1.generated.j2735.J2735;
import gov.usdot.asn1.generated.j2735.dsrc.Position3D;
import gov.usdot.asn1.generated.j2735.dsrc.Latitude;
import gov.usdot.asn1.generated.j2735.dsrc.Longitude;
import gov.usdot.asn1.generated.j2735.dsrc.TemporaryID;
import gov.usdot.asn1.generated.j2735.semi.DataReceipt;
import gov.usdot.asn1.generated.j2735.semi.DataSubscriptionCancel;
import gov.usdot.asn1.generated.j2735.semi.DataSubscriptionRequest;
import gov.usdot.asn1.generated.j2735.semi.IntersectionSituationData;
import gov.usdot.asn1.generated.j2735.semi.IntersectionSituationDataAcceptance;
import gov.usdot.asn1.generated.j2735.semi.SemiDialogID;
import gov.usdot.asn1.generated.j2735.semi.SemiSequenceID;
import gov.usdot.asn1.generated.j2735.semi.ServiceRequest;
import gov.usdot.asn1.generated.j2735.semi.ServiceResponse;
import gov.usdot.asn1.j2735.CVSampleMessageBuilder;
import gov.usdot.asn1.j2735.IntersectionSitDataBuilder;
import gov.usdot.asn1.j2735.J2735Util;
import gov.usdot.asn1.j2735.msg.ids.ConnectedVehicleMessageID;
import gov.usdot.asn1.j2735.msg.ids.SEMIMessageID;
import gov.usdot.cv.common.asn1.ConnectionPointHelper;
import gov.usdot.cv.common.dialog.DataBundle;
import gov.usdot.cv.common.dialog.DataBundleUtil;
import gov.usdot.cv.common.util.UnitTestHelper;
import gov.usdot.cv.transport.ServiceRegion;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertArrayEquals;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.lang.AssertionError;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Properties;

import org.apache.commons.io.FileUtils;

import javax.xml.bind.DatatypeConverter;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.oss.asn1.AbstractData;
import com.oss.asn1.Coder;
import com.oss.asn1.ControlTableNotFoundException;
import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;
import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;
import com.oss.asn1.ValidateFailedException;
import com.oss.asn1.ValidateNotSupportedException;

public class UDPMessageProcessorTest {
	
	static final private boolean isDebugOutput = false;
	private static Logger log = Logger.getLogger(UDPMessageProcessorTest.class);
	
	static private final String DIGEST_ALGORITHM_NAME = "SHA-256";
	
	static final String secureMessagePath = "/tmp/SecureVehSitDataMessage.uper";
	
	final private int DEFAULT_MAX_PACKET_SIZE = 65535;
	final private int DEFAULT_LISTEN_PORT = 46751;
	final private int DEST_VSD_LISTEN_PORT = DEFAULT_LISTEN_PORT + 1;
	final private int DEST_DPC_LISTEN_PORT = DEFAULT_LISTEN_PORT + 2;
	final private int DEST_INT_LISTEN_PORT = DEFAULT_LISTEN_PORT + 3;
	
	private MessageDigest messageDigest = null;
	private Coder coder = null;

	@BeforeClass
	public static void init() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
		String basedir = System.getProperty("basedir", ".");
		Properties testProperties = System.getProperties();
		testProperties.setProperty("RTWS_CONFIG_DIR", basedir + "/../commons-systems/src/systems/com.deleidos.rtws.localhost");
		System.setProperties(testProperties);
		FileUtils.deleteQuietly(new File(secureMessagePath));
	}

	@AfterClass
	public static void cleanup() {
		FileUtils.deleteQuietly(new File(secureMessagePath));
	}

	@Before
	public void setUp() throws Exception {
		initialize();
	}

	@After
	public void tearDown() throws Exception {
		dispose();
	}
	
	private class TestTransportService extends CvUDPTransportService {
		
		private final byte[] request;
		private final int destPort;
		
		public TestTransportService(byte[] request, int port) {
			super();
			this.request = request;
			this.destPort = port;
			this.setMessageFormat("DSRCJ2735");
		}

		@Override
		public void execute() {			
		}

		@Override
		public void terminate() {
		}
		
		@Override
		public void SendJMSMessage(String msg) {
			send(msg);
		}
		
		@Override
		public void SendJMSMessageAndFlush(String msg) {
			send(msg);
		}
		
		private void send(String msg) {
			DataBundle dataBundle = DataBundleUtil.decode(msg);
			assertNotNull(dataBundle);
			byte[] bytes = dataBundle.getPayload();
			assertEquals("127.0.0.1", dataBundle.getDestHost());
			assertEquals(destPort, dataBundle.getDestPort());
			assertArrayEquals(request, bytes);
		}
	}
	
	byte[] requestHash = null;
	AssertionError assertionError = null;

	@Test
	public void testVehicleServiceRequest() throws EncodeFailedException, EncodeNotSupportedException, IOException {
		testServiceRequest(SemiDialogID.vehSitData);
		testVehSitDataMessage(DEFAULT_LISTEN_PORT);
	}
	
	@Test
	public void testVehicleServiceRequestWithDestination() throws EncodeFailedException, EncodeNotSupportedException, IOException {
		testServiceRequest(SemiDialogID.vehSitData, DEST_VSD_LISTEN_PORT);
		testVehSitDataMessage(DEST_VSD_LISTEN_PORT);
	}
	
	public void testVehSitDataMessage(int dstPort) throws EncodeFailedException, EncodeNotSupportedException, IOException {
		byte[] requestPayload =  CVSampleMessageBuilder.messageToEncodedBytes(CVSampleMessageBuilder.buildVehSitDataMessage());
		
		TestTransportService reciever = new TestTransportService(requestPayload, dstPort);
		
		DatagramPacket datagramPacket = new DatagramPacket(requestPayload, requestPayload.length, InetAddress.getByName("localhost"), DEFAULT_LISTEN_PORT);
		
		UDPMessageProcessor messageProcessor = new UDPMessageProcessor(datagramPacket, reciever);
		messageProcessor.run();
		
		checkBackgroundThreadAssertion();
	}

	@Test
	public void testDPCServiceRequest() throws UnknownHostException {
		testServiceRequest(SemiDialogID.dataSubscription);
	}
	
	@Test
	public void testDPCServiceRequestWithDestination() throws UnknownHostException {
		testServiceRequest(SemiDialogID.dataSubscription, DEST_DPC_LISTEN_PORT);
	}
	
	public void testServiceRequest(SemiDialogID dialogID) throws UnknownHostException {
		testServiceRequest(dialogID, DEFAULT_LISTEN_PORT);
	}
	
	public void testServiceRequest(SemiDialogID dialogID, int listenPort) throws UnknownHostException {
		byte[] requestPayload = null;
		
		ServiceRequest request = CVSampleMessageBuilder.buildServiceRequest(J2735Util.createTemporaryID(), dialogID);
		if ( listenPort == DEST_VSD_LISTEN_PORT || listenPort == DEST_DPC_LISTEN_PORT )
			request.setDestination(ConnectionPointHelper.createConnectionPoint(listenPort));
		TemporaryID requestID = request.getRequestID();
		startUdpListener(new SEMIMessageID(dialogID.longValue(), SemiSequenceID.svcResp.longValue()), listenPort, requestID);
		
		try {
			ByteArrayOutputStream sink = new ByteArrayOutputStream();
			coder.encode(request, sink);
			requestPayload = sink.toByteArray();
			requestHash =  messageDigest.digest(requestPayload);
		} catch (EncodeFailedException ex) {
			log.error("Couldn't encode ServiceResponse message because encoding failed", ex);
			assertTrue(false);
		} catch (EncodeNotSupportedException ex) {
			log.error("Couldn't encode ServiceResponse message because encoding is not supported", ex);
			assertTrue(false);
		}
		
		TestTransportService reciever = new TestTransportService(requestPayload, listenPort);
		DatagramPacket datagramPacket = new DatagramPacket(requestPayload, requestPayload.length, InetAddress.getByName("localhost"), DEFAULT_LISTEN_PORT);
		
		UDPMessageProcessor messageProcessor = new UDPMessageProcessor(datagramPacket, reciever);
		messageProcessor.run();
		
		checkBackgroundThreadAssertion();
	}
	
	@Test
	public void testDPCSubscriptionRequestMessageProcess() throws UnknownHostException, EncodeFailedException, EncodeNotSupportedException {
		
		byte[] requestPayload =  CVSampleMessageBuilder.messageToEncodedBytes(CVSampleMessageBuilder.buildDataSubscriptionRequest());
		
		TestTransportService reciever = new TestTransportService(requestPayload, DEST_DPC_LISTEN_PORT);
		
		DatagramPacket datagramPacket = new DatagramPacket(requestPayload, requestPayload.length, InetAddress.getByName("localhost"), DEST_DPC_LISTEN_PORT);
		
		UDPMessageProcessor messageProcessor = new UDPMessageProcessor(datagramPacket, reciever);
		messageProcessor.run();
		
		checkBackgroundThreadAssertion();
	}
	
	@Test
	public void testDPCSubscriptionCancelMessageProccess() throws UnknownHostException, EncodeFailedException, EncodeNotSupportedException {		
		byte[] requestPayload =  CVSampleMessageBuilder.messageToEncodedBytes(CVSampleMessageBuilder.buildDataSubscriptionCancel());
		
		TestTransportService reciever = new TestTransportService(requestPayload, DEST_DPC_LISTEN_PORT);
		
		DatagramPacket datagramPacket = new DatagramPacket(requestPayload, requestPayload.length, InetAddress.getByName("localhost"), DEST_DPC_LISTEN_PORT);
		
		UDPMessageProcessor messageProcessor = new UDPMessageProcessor(datagramPacket, reciever);
		messageProcessor.run();
		
		checkBackgroundThreadAssertion();
	}
	
	/* 020102b14bc5c9d043052802AFE0 -- header before the payload length is added
	 * w_Digest (Signer ID Type == 02)
		version			02
		Content Type	01
		Signer ID Type	02
		Digest Value	b14bc5c9d0430528
		Message Flag	02
		PSID			AFE0
		Length			810E
		J2735 APDU	    3081e280010281260573b91c80b3...
	*/
	
	static private byte[] createSecureMessage(byte[] data) throws IOException {
		byte[] header = DatatypeConverter.parseHexBinary("020102b14bc5c9d043052802AFE0");
		byte[] length = J2735Util.shortToBytes((short)data.length);
		ByteArrayOutputStream messageStream = new ByteArrayOutputStream( );
		messageStream.write( header );
		messageStream.write( length );
		messageStream.write( data   );
		return messageStream.toByteArray();
	}

	@Test
	public void testSecureMessage() throws EncodeFailedException, EncodeNotSupportedException, IOException
	{
		byte[] payload = CVSampleMessageBuilder.messageToEncodedBytes(CVSampleMessageBuilder.buildVehSitDataMessage());
		byte[] secureMessage = createSecureMessage(payload);
		testSecureMessage(secureMessage, payload);
		
		FileUtils.writeByteArrayToFile(new File(secureMessagePath), secureMessage);
		testSecureMessageFromFile();
	}
	
	public void testSecureMessageFromFile() throws EncodeFailedException, EncodeNotSupportedException, IOException
	{
		byte[] payload = CVSampleMessageBuilder.messageToEncodedBytes(CVSampleMessageBuilder.buildVehSitDataMessage());
		byte[] secureMessage = FileUtils.readFileToByteArray(new File(secureMessagePath));
		
		testSecureMessage(secureMessage, payload);
	}
	
	public void testSecureMessage(byte[] secureMessage, byte[] payload) throws EncodeFailedException, EncodeNotSupportedException, IOException
	{		
		TestTransportService reciever = new TestTransportService(payload, DEST_VSD_LISTEN_PORT);
		reciever.setMessageFormat("IEEE1609Dot2");
		
		DatagramPacket datagramPacket = new DatagramPacket(secureMessage, secureMessage.length, InetAddress.getByName("localhost"), DEFAULT_LISTEN_PORT);
		
		UDPMessageProcessor messageProcessor = new UDPMessageProcessor(datagramPacket, reciever);
		messageProcessor.run();
		
		checkBackgroundThreadAssertion();
	}
	
	private void sendServiceRequest(final SemiDialogID dialogID, TemporaryID requestID, int listenPort) throws UnknownHostException {
		byte[] requestPayload = null;
		
		ServiceRequest request = CVSampleMessageBuilder.buildServiceRequest(requestID, dialogID);
		if ( listenPort != DEFAULT_LISTEN_PORT )
			request.setDestination(ConnectionPointHelper.createConnectionPoint(listenPort));
		
		try {
			ByteArrayOutputStream sink = new ByteArrayOutputStream();
			coder.encode(request, sink);
			requestPayload = sink.toByteArray();
			requestHash =  messageDigest.digest(requestPayload);
		} catch (EncodeFailedException ex) {
			log.error("Couldn't encode ServiceResponse message because encoding failed", ex);
			assertTrue(false);
		} catch (EncodeNotSupportedException ex) {
			log.error("Couldn't encode ServiceResponse message because encoding is not supported", ex);
			assertTrue(false);
		}
		
		TestTransportService reciever = new TestTransportService(requestPayload, listenPort);
		DatagramPacket datagramPacket = new DatagramPacket(requestPayload, requestPayload.length, InetAddress.getByName("localhost"), DEFAULT_LISTEN_PORT);
		
		UDPMessageProcessor messageProcessor = new UDPMessageProcessor(datagramPacket, reciever);
		messageProcessor.run();
		
		checkBackgroundThreadAssertion();
	}
	
	@Test
	public void testIntersectionSituationData() throws InterruptedException, EncodeFailedException, EncodeNotSupportedException, IOException {
		testIntersectionSituationData(false);
	}
	
	@Test
	public void testIntersectionSituationDataMismatch() throws InterruptedException, EncodeFailedException, EncodeNotSupportedException, IOException {
		testIntersectionSituationData(true);
	}
	
	private void testIntersectionSituationData(boolean simulateMismatch) throws InterruptedException, EncodeFailedException, EncodeNotSupportedException, IOException {
		final SemiDialogID dialogID = SemiDialogID.intersectionSitDataDep;
		final int listenPort = DEST_INT_LISTEN_PORT;

		IntersectionSituationData isd = IntersectionSitDataBuilder.buildIntersectionSituationData();
		TemporaryID requestID = isd.getRequestID();
		
		// send IntersectionSituationDataDepositServiceRequest (ServiceRequest)
		sendServiceRequest(SemiDialogID.intersectionSitDataDep,requestID, listenPort);
		// skip receiving IntersectionSituationDataDepositServiceResponse (ServiceResponse)
		Thread.sleep(200);
		
		// listen for IntersectionSituationDataReceipt (DataReceipt)
		startUdpListener(new SEMIMessageID(dialogID.longValue(), SemiSequenceID.receipt.longValue()), listenPort, requestID, 3000);
		// send IntersectionSituationData
		byte[] requestPayload;
		final int msg_count = 3; 
		for( int i = 0; i < msg_count; i++ ) {
			requestPayload = CVSampleMessageBuilder.messageToEncodedBytes(isd);
			TestTransportService reciever = new TestTransportService(requestPayload, listenPort);
			DatagramPacket datagramPacket = new DatagramPacket(requestPayload, requestPayload.length, InetAddress.getByName("localhost"), DEFAULT_LISTEN_PORT);
			UDPMessageProcessor messageProcessor = new UDPMessageProcessor(datagramPacket, reciever);
			messageProcessor.run();
			Thread.sleep(200);
		}
		// send IntersectionSituationDataAcceptance
		IntersectionSituationDataAcceptance isda = IntersectionSitDataBuilder.buildIntersectionSituationDataAcceptance(
				simulateMismatch ? msg_count + 1 : msg_count);
		requestPayload = CVSampleMessageBuilder.messageToEncodedBytes(isda);
		TestTransportService reciever = new TestTransportService(requestPayload, listenPort);
		DatagramPacket datagramPacket = new DatagramPacket(requestPayload, requestPayload.length, InetAddress.getByName("localhost"), DEFAULT_LISTEN_PORT);
		UDPMessageProcessor messageProcessor = new UDPMessageProcessor(datagramPacket, reciever);
		messageProcessor.run();
		Thread.sleep(200);
		
		checkBackgroundThreadAssertion();
	}
	
	private void initialize() {
		try {
			J2735.initialize();
			coder = J2735.getPERUnalignedCoder();
			if ( isDebugOutput  ) {
				coder.enableEncoderDebugging();
				coder.enableDecoderDebugging();
			}
		} catch (ControlTableNotFoundException ex) {
			log.error("Couldn't initialize J2735 parser", ex);
		} catch (com.oss.asn1.InitializationException ex) {
			log.error("Couldn't initialize J2735 parser", ex);
		}
		
		try {
			messageDigest = MessageDigest.getInstance(DIGEST_ALGORITHM_NAME);
		} catch (NoSuchAlgorithmException e) {
			log.error(String.format("Couldn't instantiate digest algorithm %s", DIGEST_ALGORITHM_NAME));
		}
	}
	
	private void dispose() {
		messageDigest = null;
		coder = null;
		J2735.deinitialize();
	}
	
	private void startUdpListener(ConnectedVehicleMessageID msgID, int port, TemporaryID requestID) {
		startUdpListener(msgID, port, requestID, 3000);
	}
	
	private void startUdpListener(ConnectedVehicleMessageID msgID, int port, TemporaryID requestID, int timeOut) {
		final int listenPort = port;
		final TemporaryID expectedRequestID = requestID;
		final int timeout = timeOut;
		
		Thread listener = new Thread( new Runnable() {
			public void run() {
				DatagramSocket socket = null;
				try {
					socket = new DatagramSocket(listenPort);
					socket.setSoTimeout(timeout);
					DatagramPacket datagramPacket = new DatagramPacket(new byte[DEFAULT_MAX_PACKET_SIZE], DEFAULT_MAX_PACKET_SIZE);
					socket.receive(datagramPacket);
					validatePacket(datagramPacket);
				} catch (SocketException ex) {
					log.error(String.format("Caught socket exception while recieving message on port %d. Max size is %d", listenPort, DEFAULT_MAX_PACKET_SIZE), ex);
					assertTrue(false);
				} catch (IOException ex) {
					log.error(String.format("Caught IO exception exception while recieving message on port %d. Max size is %d", listenPort, DEFAULT_MAX_PACKET_SIZE), ex);
					assertTrue(false);
				} finally {
					if ( socket != null &&  !socket.isClosed() ) {
						socket.close();
						socket = null;
					}
				}
			}
			
			void validatePacket(DatagramPacket packet) {
				assertNotNull(packet);
				
				final byte[] data = packet.getData();
				assertNotNull(data);
				
				final int length = packet.getLength();	
				assertTrue(length > 0);
				
				final int offset = packet.getOffset();

				byte[] packetData = Arrays.copyOfRange(data, offset, length);
				// add 1609.2 decoding here when it's available
				try {
					AbstractData pdu = J2735Util.decode(coder, packetData);
					
					if ( pdu instanceof ServiceResponse ) {
						validateServiceResponsePacket(pdu);
					} else if ( pdu instanceof DataSubscriptionRequest ) {
						validateDPCSubscriptionRequestPacket(pdu);
					} else if ( pdu instanceof DataSubscriptionCancel ) {
						validateDPCSubscriptionCancelPacket(pdu);
					} else if ( pdu instanceof DataReceipt ) {
						validateDataReceipt(pdu);
					} else {
						System.out.printf("Add code to hanlde new message type\n");
						assertTrue(false);
					}
					return;
					
				} catch (DecodeFailedException ex) {
					log.error("Couldn't decode J2735 ASN.1 UPER message because decoding failed", ex);
				} catch (DecodeNotSupportedException ex) {
					log.error("Couldn't decode J2735 ASN.1 UPER message because decoding is not supported", ex);				
				} catch (AssertionError ex) {
					log.error("Assertion in the background thread", ex);	
					assertionError = ex;
				}
			}
	
			void validateServiceResponsePacket(AbstractData pdu) {
				assertNotNull(pdu);
				
				try {					
					assertTrue(pdu instanceof ServiceResponse);
					
					ServiceResponse response = (ServiceResponse)pdu;
					
					TemporaryID requestID = response.getRequestID();
					assertNotNull(requestID);
					assertNotNull(expectedRequestID);
					Arrays.equals(requestID.byteArrayValue(), expectedRequestID.byteArrayValue());
					
					byte[] hash = response.getHash().byteArrayValue();
					assertTrue( Arrays.equals(requestHash, hash));
					
					ServiceRegion serviceRegion = new ServiceRegion();
					
					Position3D nwCnr = response.getServiceRegion().getNwCorner();
					assertNotNull(nwCnr);
					
					Longitude longitude = nwCnr.get_long();
					assertNotNull(longitude);
					
					assertTrue(longitude.isValid());
					int value = longitude.intValue();
					assertEquals(serviceRegion.nwCnr_Longitude, value);

					Latitude latitude = nwCnr.getLat();
					assertNotNull(latitude);
					
					assertTrue(latitude.isValid());
					value = latitude.intValue();
					assertEquals(serviceRegion.nwCnr_Latitude, value);
					
					Position3D seCnr = response.getServiceRegion().getSeCorner();
					assertNotNull(seCnr);
					
					longitude = seCnr.get_long();
					assertNotNull(longitude);
					
					assertTrue(longitude.isValid());
					value = longitude.intValue();
					assertEquals(serviceRegion.seCnr_Longitude, value);
					
					latitude = seCnr.getLat();
					assertNotNull(latitude);
					
					assertTrue(latitude.isValid());
					value = latitude.intValue();
					assertEquals(serviceRegion.seCnr_Latitude, value);
					
					return;
					
				} catch (ValidateFailedException ex) {
					log.error("Couldn't decode J2735 ASN.1 UPER message because decoding is not supported", ex);
				} catch (ValidateNotSupportedException ex) {
					log.error("Validatoin is not supported", ex);					
				} catch (AssertionError ex) {
					assertionError = ex;
				}
			}
			
			void validateDPCSubscriptionRequestPacket(AbstractData pdu) {
				assertNotNull(pdu);
				try {					
					assertTrue(pdu instanceof DataSubscriptionRequest);
					DataSubscriptionRequest response = (DataSubscriptionRequest)pdu;
					TemporaryID requestID = response.getRequestID();
					assertNotNull(requestID);
					assertNotNull(expectedRequestID);
					Arrays.equals(requestID.byteArrayValue(), expectedRequestID.byteArrayValue());
					return;					
				} catch (AssertionError ex) {
					assertionError = ex;
				}
			}
			
			void validateDPCSubscriptionCancelPacket(AbstractData pdu) {
				assertNotNull(pdu);
				try {					
					assertTrue(pdu instanceof DataSubscriptionCancel);
					DataSubscriptionCancel response = (DataSubscriptionCancel)pdu;
					TemporaryID requestID = response.getRequestID();
					assertNotNull(requestID);
					assertNotNull(expectedRequestID);
					Arrays.equals(requestID.byteArrayValue(), expectedRequestID.byteArrayValue());
					return;				
				} catch (AssertionError ex) {
					assertionError = ex;
				}
			}
			
			void validateDataReceipt(AbstractData pdu) {
				assertNotNull(pdu);
				try {					
					assertTrue(pdu instanceof DataReceipt);
					DataReceipt response = (DataReceipt)pdu;
					TemporaryID requestID = response.getRequestID();
					assertNotNull(requestID);
					assertNotNull(expectedRequestID);
					Arrays.equals(requestID.byteArrayValue(), expectedRequestID.byteArrayValue());
					log.debug("Got DataReceipt!");
					return;				
				} catch (AssertionError ex) {
					assertionError = ex;
				}
			}
			
		});
		listener.start();
		try {
			Thread.sleep(500);
		} catch (InterruptedException e) {
		}
	}	
	
	void checkBackgroundThreadAssertion() {
		try {
			Thread.sleep(3000);
		} catch (InterruptedException unused) {
		}
		
		if ( assertionError != null )
			throw assertionError;
	}
}

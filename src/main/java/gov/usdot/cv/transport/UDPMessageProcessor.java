package gov.usdot.cv.transport;

import gov.usdot.asn1.generated.j2735.J2735;
import gov.usdot.asn1.generated.j2735.dsrc.Latitude;
import gov.usdot.asn1.generated.j2735.dsrc.Longitude;
import gov.usdot.asn1.generated.j2735.dsrc.Position3D;
import gov.usdot.asn1.generated.j2735.dsrc.TemporaryID;
import gov.usdot.asn1.generated.j2735.semi.DataConfirmation;
import gov.usdot.asn1.generated.j2735.semi.DataReceipt;
import gov.usdot.asn1.generated.j2735.semi.GeoRegion;
import gov.usdot.asn1.generated.j2735.semi.GroupID;
import gov.usdot.asn1.generated.j2735.semi.SemiDialogID;
import gov.usdot.asn1.generated.j2735.semi.SemiSequenceID;
import gov.usdot.asn1.generated.j2735.semi.ServiceResponse;
import gov.usdot.asn1.generated.j2735.semi.Sha256Hash;
import gov.usdot.asn1.generated.j2735.semi.ServiceRequest;
import gov.usdot.asn1.generated.j2735.semi.DataAcceptance;
import gov.usdot.asn1.generated.j2735.semi.AdvisorySituationData;
import gov.usdot.asn1.generated.j2735.semi.IntersectionSituationDataAcceptance;
import gov.usdot.asn1.j2735.J2735Util;
import gov.usdot.cv.common.asn1.DialogIDHelper;
import gov.usdot.cv.common.dialog.DataBundleUtil;
import gov.usdot.cv.common.inet.InetPacket;
import gov.usdot.cv.common.inet.InetPacketException;
import gov.usdot.cv.common.inet.InetPacketSender;
import gov.usdot.cv.common.inet.InetPoint;
import gov.usdot.cv.logging.MessageCounting;
import gov.usdot.cv.security.cert.Certificate;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.msg.IEEE1609p2Message;
import gov.usdot.cv.security.type.MsgSignerIDType;
import gov.usdot.cv.session.Session;
import gov.usdot.cv.session.SessionMgr;
import gov.usdot.cv.session.SessionReceiptReceiver;

import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.apache.commons.codec.binary.Hex;

import org.apache.log4j.Logger;

import com.oss.asn1.AbstractData;
import com.oss.asn1.Coder;
import com.oss.asn1.ControlTableNotFoundException;
import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;
import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;

import com.deleidos.rtws.transport.AbstractTransportService;

public class UDPMessageProcessor implements Runnable {

	private static final Logger log = Logger.getLogger(UDPMessageProcessor.class);
	
	private static boolean traceEnabled = log.isTraceEnabled();
	
	static private final String DIGEST_ALGORITHM_NAME = "SHA-256";
	
	private MessageDigest messageDigest = null;
	private Coder coder = null;
	
	private DatagramPacket packet;
	private AbstractTransportService reciever;
	
	private final ServiceRegion serviceRegion;
	private final boolean isIEEE1609DotMessageFormat;
	private CryptoProvider cryptoProvider;
	public static final int Psid = 0x2fe1;

	private final InetAddress forwarderInetAddress;
	private final Boolean forwardingRequested;	// false - forward not requested, true - forward requested, null - forward requested but can not be fulfilled	
	private final int forwarderPort;
	
	static final SessionMgr sessionMgr = new SessionMgr(); 
	static SessionReceiptReceiver receiptReceiver = null;

	public UDPMessageProcessor(DatagramPacket packet, AbstractTransportService reciever) {
		this.packet = packet;
		this.reciever = reciever;
		
		assert(reciever instanceof CvUDPTransportService);
		CvUDPTransportService transportService =  (CvUDPTransportService)reciever;
		serviceRegion = transportService.getServiceRegion();
		isIEEE1609DotMessageFormat = transportService.MESSAGE_FORMAT_DEFAULT.equals(transportService.getMessageFormat());
		forwardingRequested = transportService.getForwardRequested();
		forwarderInetAddress = transportService.getForwardInetAddress();	
		forwarderPort = transportService.getForwarderPort();
	}
	
	public void run() {
		try {
			initialize();
			processMessage();
		} catch (Exception ex ) {
			log.error("Couldn't process message", ex );			
		} finally {
			dispose();
		}
	}
	
	private void initialize() {
		try {
			cryptoProvider = new CryptoProvider();
			J2735.initialize();
			coder = J2735.getPERUnalignedCoder();
			if ( traceEnabled ) {
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

	private void processMessage() throws UnknownHostException {
		if ( packet == null )
			return;
		
		final byte[] data = packet.getData();
		final int length = packet.getLength();	
		
		if ( data == null || length <= 0 )
			return;
		
		final int offset = packet.getOffset();
		final InetAddress address = packet.getAddress();
		final int port = packet.getPort();

		byte[] packetData = Arrays.copyOfRange(data, offset, length);
		
		if ( packetData == null || packetData.length == 0 )
			return; 
		
		MessageCounting.incrementTotal(CvUDPTransportService.loggerIndex);
		
		// original packet data could be prepended with the IPv6 forwarder header so we need to parse it out here
		InetPacket inetPacket = new InetPacket(address, port, packetData);
		byte[] origPacketData = inetPacket.getPayload();
		
		byte[] payload;
		byte[] certBytes;
		byte[] certID8;
		Boolean isDigest = null; // null -- not 1609.2, true -- 1609.2 with digest, false -- 1609.2 with certificate 
		
		if ( isIEEE1609DotMessageFormat ) {
			try {
				IEEE1609p2Message msg = IEEE1609p2Message.parse(origPacketData, cryptoProvider);
				payload = msg.getPayload();
				Certificate cert = msg.getCertificate();
				certBytes = cert.getBytes();
				certID8 = msg.getCertID8();
				isDigest = msg.getSignerIDType() != MsgSignerIDType.Certificate;
				log.debug("Received and successfully parsed 1609.2 message with " + (isDigest == true ? "digest" : "certificate") + " from sender with digest: " + Hex.encodeHexString(certID8));
			} catch ( Exception ex ) {
				log.error("Error parsing IEEE 1609.2 message. Reason: " + ex.getMessage(), ex);
				log.error("Failed message bytes:  " + Hex.encodeHexString(origPacketData));
				return;
			}
		} else {
			payload = origPacketData;
			certBytes = certID8 = null;
		}
		
		if ( payload == null || payload.length == 0 )
			return;
		
		log.debug(String.format("Received packet from host %s, port %d. Paylaod: %s\nBundle: %s", 
				address.getHostAddress(), port, payload != null ? Hex.encodeHexString(payload) : "<null>", inetPacket.toHexString()));
		
		AbstractData pdu = null;
		try {
			pdu = J2735Util.decode(coder, payload);
		} catch (DecodeFailedException ex) {
			log.error("Couldn't decode message because decoding failed", ex);
			return;
		} catch (DecodeNotSupportedException ex) {
			log.error("Couldn't decode message because decoding is not supported", ex);
			return;
		}

		Session session = sessionMgr.getSession(inetPacket.getPoint(), pdu, certBytes, certID8);
		
		if ( session == null ) {
			log.warn(String.format("Dropping out of sequence message from host '%s', port %d. Msg: %s", address.getHostAddress(), port, pdu));
			return;
		}
		
		InetPoint destination = session.getDestination();
		if ( destination == null )
			destination = session.getSessionKey().source;
		byte[] recipient =  session.getCertID8(); 
		if ( pdu instanceof ServiceRequest ) {
			log.debug("Received ServiceRequest");
			ServiceRequest serviceRequest = (ServiceRequest)pdu;
			sendServiceResponse(payload, destination, serviceRequest.getDialogID(),  serviceRequest.getGroupID(), serviceRequest.getRequestID(), recipient);
		} else if ( reciever != null && payload != null && payload.length > 0 ) {
			if ( pdu instanceof IntersectionSituationDataAcceptance ) {
				sendDataReceipt(session, (IntersectionSituationDataAcceptance)pdu, destination, recipient);
			} else if ( pdu instanceof DataAcceptance ) {
				sendDataReceipt(session, (DataAcceptance)pdu, destination, recipient);
			} else {
				processMessage(session, payload, DialogIDHelper.getDialogID(pdu));
				if ( pdu instanceof AdvisorySituationData ) {
					AdvisorySituationData asdc = (AdvisorySituationData)pdu;
					sendDataConfirmation(payload, destination, asdc.getDialogID(), asdc.getGroupID(), asdc.getRequestID(), recipient);
				}
			}
		}
	}

	private void sendServiceResponse(byte[] packetData, InetPoint destination, SemiDialogID dialogID, GroupID groupID, TemporaryID requestID, byte[] recipient) {
		log.debug("called sendServiceResponse");
		if ( requestID == null ) {
			log.warn("Received Service Request with null request ID. Random ID will be used in the Service Response");
			requestID = J2735Util.createTemporaryID();
		}
		
		byte[] packetHash = messageDigest.digest(packetData);
		byte[] responseBytes = formatServiceResponsePayload(packetHash, dialogID, groupID, requestID);
		if ( responseBytes != null && responseBytes.length > 0 ) {
			byte[] responsePayload = to1609_2( responseBytes, recipient, false );
			if ( responsePayload != null )
				send(destination, responsePayload);
		}
	}
	
	private void sendDataConfirmation(byte[] packetData, InetPoint destination, SemiDialogID dialogID, GroupID groupID, TemporaryID requestID, byte[] recipient) {
		log.debug("called sendDataConfirmation");
		if ( requestID == null ) {
			log.warn("Dropping message with null request ID.");
			return;
		}
		log.debug("sendDataConfirmation: payload: " + Hex.encodeHexString(packetData));
		byte[] packetHash = messageDigest.digest(packetData);
		log.debug("sendDataConfirmation: packetHash: " + Hex.encodeHexString(packetHash));
		byte[] responseBytes = formatDataConfirmationPayload(packetHash, dialogID, groupID, requestID);
		if ( responseBytes != null && responseBytes.length > 0 ) {
			byte[] responsePayload = to1609_2( responseBytes, recipient, true );
			if ( responsePayload != null )
				send(destination, responsePayload);
		}
	}
	
	private void sendDataReceipt(Session session, IntersectionSituationDataAcceptance isda, InetPoint destination, byte[] recipient) {
		assert(isda != null);
		log.debug("called sendDataReceipt for IntersectionSituationDataAcceptance");
		final SemiDialogID dialogID = isda.getDialogID(); 
		final GroupID groupID = isda.getGroupID();
		final TemporaryID requestID = isda.getRequestID();
		int recordsSent = (int)isda.getRecordsSent();
		final int recordsReceived = session.getCount();
		session.close();
		log.debug(String.format("Records sent: %d, records received: %d", recordsSent, recordsReceived));
		if ( recordsSent == recordsReceived ) {
			if ( requestID != null ) {
				byte[] responseBytes = formatDataReceiptPayload(dialogID, groupID, requestID);
				if ( responseBytes != null && responseBytes.length > 0 ) {
					byte[] responsePayload = to1609_2( responseBytes, recipient, true );
					if ( responsePayload != null )
						send(destination, responsePayload);
				}
			} else {
				log.warn("Dropping message with null request ID.");
			}
		} else {
			log.warn(String.format("Data acceptance message for session: %s indicates sent/received mismatch.\n\tRecords sent: %d, records received: %d.\n\tData receipt for this session will not be sent.", session.getSessionKey(), recordsSent, recordsReceived));
		}
	}
	
	private void sendDataReceipt(Session session, DataAcceptance da, InetPoint destination, byte[] recipient) {
		assert(da != null);
		log.debug("called sendDataReceipt for DataAcceptance");
		final SemiDialogID dialogID = da.getDialogID(); 
		final GroupID groupID = da.getGroupID();
		final TemporaryID requestID = da.getRequestID();
		session.close();
		if ( requestID != null ) {
			byte[] responseBytes = formatDataReceiptPayload(dialogID, groupID, requestID);
			if ( responseBytes != null && responseBytes.length > 0 ) {
				byte[] responsePayload = to1609_2( responseBytes, recipient, true );
				if ( responsePayload != null )
					send(destination, responsePayload);
			}
		} else {
			log.warn("Dropping message with null request ID.");
		}
	}
	
	private byte[] formatServiceResponsePayload(byte[] hashBytes, SemiDialogID dialogID, GroupID groupID, TemporaryID requestID)
	{	
		Sha256Hash hash = new Sha256Hash(hashBytes);

		Position3D nwCnr = new Position3D(new Latitude(serviceRegion.nwCnr_Latitude), new Longitude(serviceRegion.nwCnr_Longitude));
		Position3D seCnr = new Position3D(new Latitude(serviceRegion.seCnr_Latitude), new Longitude(serviceRegion.seCnr_Longitude));
		GeoRegion svcGeoRegion = new GeoRegion(nwCnr, seCnr);
		ServiceResponse response = new ServiceResponse(dialogID, SemiSequenceID.svcResp, groupID, requestID, J2735Util.expireInMin(1), svcGeoRegion, hash);
		
		try {
			ByteArrayOutputStream sink = new ByteArrayOutputStream();
			coder.encode(response, sink);
			byte[] responseBytes = sink.toByteArray();
			return responseBytes;
		} catch (EncodeFailedException ex) {
			log.error("Couldn't encode ServiceResponse message because encoding failed", ex);
		} catch (EncodeNotSupportedException ex) {
			log.error("Couldn't encode ServiceResponse message because encoding is not supported", ex);
		}
		
		return null;
	}
	
	private byte[] formatDataConfirmationPayload(byte[] hashBytes, SemiDialogID dialogID, GroupID groupID, TemporaryID requestID)
	{	
		Sha256Hash hash = new Sha256Hash(hashBytes);
		AbstractData pdu = null;
		pdu = new DataConfirmation(dialogID, SemiSequenceID.dataConf, groupID, requestID, hash);		
		try {
			ByteArrayOutputStream sink = new ByteArrayOutputStream();
			coder.encode(pdu, sink);
			return sink.toByteArray();
		} catch (EncodeFailedException ex) {
			log.error("Couldn't encode DataConfirmation message because encoding failed", ex);
		} catch (EncodeNotSupportedException ex) {
			log.error("Couldn't encode DataConfirmation message because encoding is not supported", ex);
		}
		return null;
	}
	
	private byte[] formatDataReceiptPayload(SemiDialogID dialogID, GroupID groupID, TemporaryID requestID)
	{	
		DataReceipt pdu = new DataReceipt(dialogID, SemiSequenceID.receipt, groupID, requestID);		
		try {
			ByteArrayOutputStream sink = new ByteArrayOutputStream();
			coder.encode(pdu, sink);
			return sink.toByteArray();
		} catch (EncodeFailedException ex) {
			log.error("Couldn't encode DataConfirmation message because encoding failed", ex);
		} catch (EncodeNotSupportedException ex) {
			log.error("Couldn't encode DataConfirmation message because encoding is not supported", ex);
		}
		return null;
	}
	
	private void send(InetPoint destination, byte[] payload) {
		try {
			if ( forwardingRequested != null && forwardingRequested == true && destination.forward ) {
				InetPoint forwarder = new InetPoint(forwarderInetAddress.getAddress(), forwarderPort);
				InetPacketSender sender = new InetPacketSender(forwarder);
				sender.setForwardAll(true);
				log.debug(String.format("Forwarding to host: %s, port: %d for destination: %s", forwarderInetAddress.getHostAddress(), forwarderPort, destination));
				sender.forward(destination, payload);
			} else {
				InetPacketSender sender = new InetPacketSender();
				log.debug(String.format("Sending directly to destination: %s", destination));
				sender.send(destination, payload);
			}
		} catch (InetPacketException ex) {
			log.error(String.format("Couldn't send ServiceResponse to address %s (bytes hex encoded), port %d", Hex.encodeHexString(destination.address), destination.port), ex);
		}
	}

	private void processMessage(Session session, byte[] payloadData, SemiDialogID dialogID) throws UnknownHostException {
		log.debug("called processMessage");
		String recievedPayload = encodePayload(session, payloadData);
		AbstractTransportService transportSvc = HelperTransports.map.get(dialogID);
		MessageCounting.incrementSuccess(CvUDPTransportService.loggerIndex);
		if ( transportSvc != null ) {
			log.debug(String.format("Sending message type '%s' via transport with input-format '%s'", DialogIDHelper.getDialogID(dialogID), transportSvc.getInputFormat()));
			transportSvc.SendJMSMessage(recievedPayload);
		} else {
			log.debug(String.format("Sending message type '%s' via  default transport", DialogIDHelper.getDialogID(dialogID)));
			reciever.SendJMSMessage(recievedPayload);
		}
	}
	
	private String encodePayload(Session session, byte[] payloadData) throws UnknownHostException {
		assert(session != null);
		InetPoint destPoint = session.getDestination();
		if ( destPoint == null )
			destPoint = session.getSessionKey().source;
		assert(destPoint != null);
		return DataBundleUtil.encode(session.getSessionID().getBytes(), destPoint.getInetAddress().getHostAddress().getBytes(), destPoint.port, destPoint.forward, session.getCertificate(), payloadData);
	}
		
	private byte[] to1609_2(byte[] payload, byte[] recipient, boolean encrypt) {
		if ( !isIEEE1609DotMessageFormat )
			return payload;
		IEEE1609p2Message msg = new IEEE1609p2Message(cryptoProvider);
		msg.setPSID(Psid);
		try {
			return encrypt ? msg.encrypt(payload, recipient) : msg.sign(payload);
		} catch (Exception ex) {
			log.error(String.format("Couldn't %s message for recipient %s. Reason: %s", 
				encrypt ? "encrypt" : "sign", recipient != null ? Hex.encodeHexString(recipient) : "<null>", ex.getMessage()), ex);
			return null;
		}
	}

}

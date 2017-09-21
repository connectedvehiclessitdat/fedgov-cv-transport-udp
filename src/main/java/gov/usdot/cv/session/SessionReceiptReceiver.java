package gov.usdot.cv.session;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.util.ListIterator;

import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

import com.oss.asn1.AbstractData;
import com.oss.asn1.Coder;
import com.oss.asn1.ControlTableNotFoundException;
import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;

import gov.usdot.asn1.generated.j2735.J2735;
import gov.usdot.asn1.generated.j2735.dsrc.TemporaryID;
import gov.usdot.asn1.generated.j2735.semi.DataReceipt;
import gov.usdot.asn1.generated.j2735.semi.GroupID;
import gov.usdot.asn1.generated.j2735.semi.SemiDialogID;
import gov.usdot.asn1.generated.j2735.semi.SemiSequenceID;
import gov.usdot.cv.common.asn1.GroupIDHelper;
import gov.usdot.cv.common.asn1.TemporaryIDHelper;
import gov.usdot.cv.common.dialog.Receipt;
import gov.usdot.cv.common.dialog.ReceiptReceiver;
import gov.usdot.cv.common.dialog.ReceiptReceiverException;
import gov.usdot.cv.common.inet.InetPacketException;
import gov.usdot.cv.common.inet.InetPacketSender;
import gov.usdot.cv.common.inet.InetPoint;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.msg.IEEE1609p2Message;
import gov.usdot.cv.transport.UDPMessageProcessor;

public class SessionReceiptReceiver extends ReceiptReceiver {
	
	private static final Logger log = Logger.getLogger(SessionReceiptReceiver.class);
	
	private static boolean traceEnabled = log.isTraceEnabled();
	
	private Coder coder = null;
	
	private SessionMgr sessionMgr = null;
	private InetAddress forwarderAddress = null;
	private int forwarderPort = 0;
	private CryptoProvider cryptoProvider = new CryptoProvider();

	public SessionReceiptReceiver(String topicName) {
		super(topicName);
	}
	
	public SessionReceiptReceiver(String receiptJmsHost, int receiptJmsPort, String topicName) {
		super(receiptJmsHost, receiptJmsPort, topicName);
	}
	
	public void setSessionMgr(SessionMgr sessionMgr) {
		this.sessionMgr = sessionMgr;
	}
	
	public void setForwarderAddress(InetAddress forwarderAddress) {
		this.forwarderAddress = forwarderAddress;
	}
	
	public void setForwarderPort(int forwarderPort) {
		this.forwarderPort = forwarderPort;
	}
	
	@Override
	public void initialize() throws ReceiptReceiverException {
		super.initialize();
		try {
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
	}
	
	@Override
	public void dispose() throws ReceiptReceiverException {
		coder = null;
		J2735.deinitialize();
		super.dispose();
	}
	
	
	@Override
	protected void processReceipts() {
		synchronized(receipts) {
			ListIterator<Receipt> iter = receipts.listIterator();
			while(iter.hasNext())
			    if( processReceipt(iter.next()) )
			        iter.remove();
		}
	}
	
	private boolean processReceipt(Receipt receipt) {
		assert(sessionMgr != null);
		log.debug(String.format("Processing Receipt: '%s'", receipt));
		String sessionID = receipt.getReceiptId();
		if ( sessionID == null )
			return true;
		Session session = sessionMgr.getSession(sessionID);
		if ( session == null || session.isInactive() )
			return true;
		log.debug(String.format("Processing Receipt for session: '%s'", session));
		if ( session.hasSeqID(SemiSequenceID.accept) ) {
			sendReceipt(session);
			session.close();
			return true;
		}
		return false;
	}
	
	private void sendReceipt(Session session) {
		assert(session != null);
		SessionKey sessionKey = session.getSessionKey();
		SemiDialogID dialogID = SemiDialogID.valueOf(sessionKey.dialogID);
		if ( dialogID == SemiDialogID.advSitDatDist || dialogID == SemiDialogID.intersectionSitDataQuery ||
			 dialogID == SemiDialogID.objReg || dialogID == SemiDialogID.objDisc) {
			GroupID groupID = GroupIDHelper.toGroupID(sessionKey.groupID);
			TemporaryID requestID = TemporaryIDHelper.toTemporaryID(sessionKey.requestID);
			AbstractData pdu = new DataReceipt(dialogID, SemiSequenceID.receipt, groupID, requestID);
			InetPoint destination = session.getDestination();
			if ( destination == null )
				destination = sessionKey.source;
			send(destination, pdu, session.getCertID8());
		}
	}
	
	private void send(InetPoint destination, AbstractData pdu, byte[] recipient ) {
		assert(destination != null);
		try {
			ByteArrayOutputStream sink = new ByteArrayOutputStream();
			coder.encode(pdu, sink);
			byte[] payload = sink.toByteArray();
			if ( recipient != null )
				payload = encrypt(payload, recipient);
			send(destination, payload);
		} catch (EncodeFailedException ex) {
			log.error("Couldn't encode receipt message because encoding failed", ex);
		} catch (EncodeNotSupportedException ex) {
			log.error("Couldn't encode receipt message because encoding is not supported", ex);
		}
	}
	
	private void send(InetPoint client, byte[] payload) {
		try {
			if ( forwarderAddress != null && client.forward ) {
				InetPoint forwarder = new InetPoint(forwarderAddress.getAddress(), forwarderPort);
				InetPacketSender sender = new InetPacketSender(forwarder);
				sender.setForwardAll(true);
				log.debug(String.format("Forwarding to host: %s, port: %d for client: %s", forwarderAddress.getHostAddress(), forwarderPort, client));
				sender.forward(client, payload);
			} else {
				InetPacketSender sender = new InetPacketSender();
				log.debug(String.format("Sending directly to client: %s", client));
				sender.send(client, payload);
			}
		} catch (InetPacketException ex) {
			log.error(String.format("Couldn't send ServiceResponse to address %s (bytes hex encoded), port %d", Hex.encodeHexString(client.address), client.port), ex);
		}
	}
	
	private byte[] encrypt(byte[] payload, byte[] recipient) {
		IEEE1609p2Message msg1609p2 = new IEEE1609p2Message(cryptoProvider);
		msg1609p2.setPSID(UDPMessageProcessor.Psid);
		try {
			if ( recipient != null ) {
				log.debug("Encrypting receipt message for recipient: " + Hex.encodeHexString(recipient)); //  
				return msg1609p2.encrypt(payload, recipient);
			}
			log.error("Couldn't encrypt outgoing message. Reason: Recipient certificate is not available (probably due to ignored failed trust establishment)" ); 
		} catch (Exception ex) {
			log.error("Couldn't encrypt outgoing message. Reason: " + ex.getMessage(), ex);
		}
		return payload;
	}
	
}

package gov.usdot.cv.transport;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

import com.deleidos.rtws.transport.AbstractTransportService;
import com.oss.asn1.AbstractData;
import com.oss.asn1.Coder;
import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;

import gov.usdot.asn1.generated.j2735.J2735;
import gov.usdot.asn1.generated.j2735.semi.SemiDialogID;
import gov.usdot.asn1.j2735.J2735Util;
import gov.usdot.cv.common.asn1.DialogIDHelper;
import gov.usdot.cv.common.dialog.DataBundleUtil;
import gov.usdot.cv.common.inet.InetPoint;
import gov.usdot.cv.logging.MessageCounting;
import gov.usdot.cv.session.Session;
import gov.usdot.cv.session.SessionKey;
import gov.usdot.cv.session.SessionMgr;
import gov.usdot.cv.websocket.BaseWebSocket;
import gov.usdot.cv.websocket.WebSocketMessageProcessor;
import gov.usdot.cv.websocket.WebSocketServer;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

public class WSMessageProcessor implements WebSocketMessageProcessor {

	private static final Logger logger = Logger.getLogger(WSMessageProcessor.class
			.getName());
	
	public static final int loggerIndex = MessageCounting.register(WSMessageProcessor.class.getSimpleName());
	
	private final static String ENCODE_TYPE = "encodeType";
	private final static String ENCODED_MSG = "encodedMsg";
	private final static String ENCODE_TYPE_HEX = "hex";
	private final static String ENCODE_TYPE_BASE64 = "base64";
	private final static String ENCODE_TYPE_UPER = "uper";
	
	private AbstractTransportService defaultTransportService;
	private WebSocketServer wsServer;
	private Coder coder;
	
	static {
		try {
			J2735.initialize();
		} catch (Exception e) {
			logger.error("Failed to initialize J2735 ", e);
		}
	}
	
	public WSMessageProcessor(AbstractTransportService transportService, WebSocketServer wsServer) {
		this.defaultTransportService = transportService;
		this.wsServer = wsServer;
		coder = J2735.getPERUnalignedCoder();
	}
	
	public void processMessage(BaseWebSocket socket, String message) {
		logger.debug("Received message: " + message);
		
		MessageCounting.incrementTotal(loggerIndex);
		
		try {
			byte[] payloadData = validateDepositMessage(message);
			AbstractData pdu = J2735Util.decode(coder, payloadData);
			
			InetPoint destPoint = new InetPoint(InetAddress.getLocalHost().getAddress(), 80);
			SemiDialogID dialogID = DialogIDHelper.getDialogID(pdu);
			SessionKey sessionKey = new SessionKey(destPoint, dialogID);
			Session session = new Session(sessionKey, SessionMgr.DEFAULT_META_SESSION_TTL);
			
			String recievedPayload = DataBundleUtil.encode(session.getSessionID().getBytes(), 
					destPoint.getInetAddress().getHostAddress().getBytes(), destPoint.port, 
					destPoint.forward, session.getCertificate(), payloadData);
			
			AbstractTransportService transportService = HelperTransports.map.get(dialogID);
			if (transportService == null)
				transportService = defaultTransportService;
			
			logger.debug(String.format("Sending message type '%s' via transport with input-format '%s'", 
					DialogIDHelper.getDialogID(dialogID), transportService.getInputFormat()));
			
			MessageCounting.incrementSuccess(loggerIndex);
			
			transportService.SendJMSMessage(recievedPayload);
			
		} catch (DepositException de) {
			logger.error("Invalid deposit message ", de);
			wsServer.sendMessage(socket, "ERROR: " + de.getMessage());
		} catch (UnknownHostException uhe) {
			logger.error("UnknownHost ", uhe);
			wsServer.sendMessage(socket, "ERROR: " + uhe.getMessage());
		} catch (DecodeFailedException dfe) {
			logger.error("DecodeFailed ", dfe);
			wsServer.sendMessage(socket, "ERROR: " + dfe.getMessage());
		} catch (DecodeNotSupportedException dnse) {
			logger.error("DecodeNotSupported ", dnse);
			wsServer.sendMessage(socket, "ERROR: " + dnse.getMessage());
		}
	}
	
	private byte[] validateDepositMessage(String message) throws DepositException {
		JSONObject json = (JSONObject)JSONSerializer.toJSON(message);
		byte[] bytes = null;
		StringBuilder errorMsg = new StringBuilder();
		if (json.containsKey(ENCODE_TYPE) && json.containsKey(ENCODED_MSG)) {
			String encodeType = json.getString(ENCODE_TYPE);
			String encodedMsg = json.getString(ENCODED_MSG);
			
			if (!encodeType.equalsIgnoreCase(ENCODE_TYPE_HEX) && !encodeType.equalsIgnoreCase(ENCODE_TYPE_BASE64) 
					&& !encodeType.equalsIgnoreCase(ENCODE_TYPE_UPER)) {
				errorMsg.append("Invalid encodeType: ").append(encodeType).
					append(", not one of the supported encodeType: ")
						.append(ENCODE_TYPE_HEX).append(", ")
						.append(ENCODE_TYPE_BASE64).append(", ")
						.append(ENCODE_TYPE_UPER);
			}
			
			if (encodeType.equalsIgnoreCase(ENCODE_TYPE_HEX) || encodeType.equalsIgnoreCase(ENCODE_TYPE_UPER)) {
				try {
					bytes = Hex.decodeHex(encodedMsg.toCharArray());
				} catch (DecoderException e) {
					errorMsg.append("Hex to bytes decoding failed: " + e.toString());
				}
			} else if (encodeType.equalsIgnoreCase(ENCODE_TYPE_BASE64)) {
				bytes = Base64.decodeBase64(encodedMsg);
			}
			
		} else {
			errorMsg.append("Deposit message missing required field(s): ");
			if (!json.containsKey(ENCODE_TYPE))
				errorMsg.append(ENCODE_TYPE).append(" ");
			if (!json.containsKey(ENCODED_MSG))
				errorMsg.append(ENCODED_MSG).append(" ");
		}
		
		if (errorMsg.length() > 0) {
			throw new DepositException(errorMsg.toString());
		}
		return bytes;
	}
	
	private class DepositException extends Exception {

		private static final long serialVersionUID = 7250633998326302977L;

		public DepositException(String message) {
			super(message);
	    }
	}
}

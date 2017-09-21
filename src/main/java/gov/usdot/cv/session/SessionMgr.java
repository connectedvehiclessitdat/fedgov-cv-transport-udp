package gov.usdot.cv.session;

import gov.usdot.asn1.generated.j2735.dsrc.TemporaryID;
import gov.usdot.asn1.generated.j2735.semi.AdvisorySituationData;
import gov.usdot.asn1.generated.j2735.semi.ConnectionPoint;
import gov.usdot.asn1.generated.j2735.semi.DataAcceptance;
import gov.usdot.asn1.generated.j2735.semi.DataConfirmation;
import gov.usdot.asn1.generated.j2735.semi.DataRequest;
import gov.usdot.asn1.generated.j2735.semi.DataSubscriptionCancel;
import gov.usdot.asn1.generated.j2735.semi.DataSubscriptionRequest;
import gov.usdot.asn1.generated.j2735.semi.GroupID;
import gov.usdot.asn1.generated.j2735.semi.IPv4Address;
import gov.usdot.asn1.generated.j2735.semi.IPv6Address;
import gov.usdot.asn1.generated.j2735.semi.IntersectionSituationData;
import gov.usdot.asn1.generated.j2735.semi.IntersectionSituationDataAcceptance;
import gov.usdot.asn1.generated.j2735.semi.IpAddress;
import gov.usdot.asn1.generated.j2735.semi.ObjectDiscoveryDataRequest;
import gov.usdot.asn1.generated.j2735.semi.ObjectRegistrationData;
import gov.usdot.asn1.generated.j2735.semi.SemiDialogID;
import gov.usdot.asn1.generated.j2735.semi.SemiSequenceID;
import gov.usdot.asn1.generated.j2735.semi.ServiceRequest;
import gov.usdot.asn1.generated.j2735.semi.VehSitDataMessage;
import gov.usdot.cv.common.asn1.DialogIDHelper;
import gov.usdot.cv.common.inet.InetPoint;

import java.util.Map.Entry;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.log4j.Logger;

import com.oss.asn1.AbstractData;

public class SessionMgr {
	
	private static final Logger log = Logger.getLogger(SessionMgr.class);

	private static final int DEFAULT_SESSION_TTL 	  = 20*1000; 	// 20 seconds of inactivity
	private static final int DEFAULT_PURGE_INTERVAL   = 10*1000;	// 10 seconds
	public static final int DEFAULT_META_SESSION_TTL  = 60*1000;	// 1 min
	
	//
	// Session Map
	//
	
	public static final int initialCapacity = 16;
	public static final float loadFactor = 0.9f;
	public static final int concurrencyLevel = 1; // let's keep it simple until we have some benchmarks with real loads
	
	// We use Object type for the key so we can index by both SessionKey and SessionID (i.e. String)
	// in one map and thus avoid creating and synchronizing two maps. This reduces the overhead
	// and is very safe because StringKey and SessionID are never the same
	private final ConcurrentHashMap<Object, Session> sessions = new ConcurrentHashMap<Object, Session>(initialCapacity, loadFactor, concurrencyLevel);
	private final int sessionTimeToLive;
	private final int sessionPurgeInterval;
	
	//
	// Session Manager
	//
	
	/**
	 * Default constructor
	 */
	public SessionMgr() {
		this(DEFAULT_SESSION_TTL, DEFAULT_PURGE_INTERVAL);
	}
	
	/**
	 * Custom constructor
	 * @param sessionTimeToLive Session time to live in milliseconds
	 * @param sessionPurgeInterval Session purge interval in milliseconds
	 */
	public SessionMgr(int sessionTimeToLive, int sessionPurgeInterval) {
		this.sessionTimeToLive = sessionTimeToLive;
		this.sessionPurgeInterval = sessionPurgeInterval;
	}
	
	/**
	 * Initializes Session Manager
	 */
	public void initialize() {
		startSessionPurger();
	}
	
	/**
	 * Disposes Session Manager
	 */
	public void dispose() {
		stopSessionPurger();
		sessions.clear();
	}
	
	/**
	 * Finds or creates a session for the received packet and returns it
	 * @param address IP address of the source for which to find or create session
	 * @param port port of the source for which to find or create session
	 * @param pdu CV ASN.1 UPER message for which to find a session
	 * @return Finds or creates session for the received packet
	 */
	public Session getSession(byte[] address, int port, AbstractData pdu) {
		return getSession(new InetPoint(address, port), pdu, null, null);
	}
	
	/**
	 * Finds or creates a session for the received packet and returns it
	 * @param address IP address of the source for which to find or create session
	 * @param port port of the source for which to find or create session
	 * @param pdu CV ASN.1 UPER message for which to find a session
	 * @param certificate to use for replies in this session 
	 * @param certID8 digest of the certificate to use for replies in this session
	 * @return Finds or creates session for the received packet
	 */
	public Session getSession(byte[] address, int port, AbstractData pdu, byte[] certificate, byte[] certID8) {
		return getSession(new InetPoint(address, port), pdu, certificate, certID8);
	}
	
	/**
	 * Finds or creates a session for the received packet and returns it
	 * @param source InetPoint for which to find or create session
	 * @param pdu CV ASN.1 UPER message for which to find a session
	 * @param certificate to use for replies in this session
	 * @param certID8 digest of the certificate to use for replies in this session
	 * @return Session ID for the newly create or found session
	 */
	public Session getSession(InetPoint source, AbstractData pdu, byte[] certificate, byte[] certID8) {
		// Trust establishment always results in a meta session being created so destination and certificate are available 
		if ( pdu instanceof ServiceRequest ) {
			Session metaSession = createMetaSession((ServiceRequest)pdu, source, certificate, certID8);
			ServiceRequest serviceRequest = (ServiceRequest)pdu;
			SemiDialogID dialogID = serviceRequest.getDialogID();
			if ( dialogID != SemiDialogID.intersectionSitDataDep && dialogID != SemiDialogID.advSitDataDep && dialogID != SemiDialogID.objReg )
				return metaSession;
		}
		// Some messages are part of a trivial dialog, do not need a separate session, and just share a meta session
		if ( pdu instanceof VehSitDataMessage || pdu instanceof DataSubscriptionRequest || pdu instanceof DataSubscriptionCancel )
			return getMetaSession(source, pdu); 
		// In most cases new session starts with the trust establishment but for some dialogs that is not true
		SemiDialogID dialogID = null;
		GroupID groupID = null;
		TemporaryID requestID = null;
		SemiSequenceID seqID = null;
		if ( pdu instanceof DataRequest ) {
			DataRequest rasdr = (DataRequest)pdu;
			dialogID = rasdr.getDialogID();
			assert(dialogID == SemiDialogID.advSitDatDist || dialogID == SemiDialogID.intersectionSitDataQuery);
			seqID = rasdr.getSeqID();
			groupID = rasdr.getGroupID();
			requestID = rasdr.getRequestID();
		} else if ( pdu instanceof ObjectDiscoveryDataRequest ) {
			ObjectDiscoveryDataRequest objDisc = (ObjectDiscoveryDataRequest)pdu;
			dialogID = objDisc.getDialogID();
			assert(dialogID == SemiDialogID.objDisc);
			seqID = objDisc.getSeqID();
			groupID = objDisc.getGroupID();
			requestID = objDisc.getRequestID();
		} else if ( pdu instanceof ServiceRequest ) {
			ServiceRequest serviceRequest = (ServiceRequest)pdu;
			dialogID = serviceRequest.getDialogID();
			seqID = serviceRequest.getSeqID();
			groupID = serviceRequest.getGroupID();
			requestID = serviceRequest.getRequestID();
		}
		if ( dialogID != null && requestID != null && groupID != null)
			return createSession(source, dialogID, seqID, groupID, requestID);
		// The message is not a start of a new session so find an existing one
		return findSession(source, pdu);
	}
	
	/**
	 * Fetch session by session ID
	 * @param sessionID UUID based session ID
	 * @return Session object
	 */
	public Session getSession(String sessionID) {
		return sessions.get(sessionID);
	}
	
	private Session createSession(InetPoint source, SemiDialogID dialogID, SemiSequenceID seqID, GroupID groupID, TemporaryID requestID) {
		SessionKey sessionKey = new SessionKey(source, dialogID, groupID, requestID);
		Session session = new Session(sessionKey, calculateSessionTimeToLive(dialogID));
		Session metaSession = getMetaSession(source, dialogID);
		if ( metaSession != null ) {
			session.setDestination(metaSession.getDestination());
			session.setCertificate(metaSession.getCertificate());
			session.setCertID8(metaSession.getCertID8());
			metaSession.touch();
		}
		session.putSeqID(seqID);
		String sessionID = session.getSessionID();
		sessions.put(sessionKey, session);
		sessions.put(sessionID,  session);
		log.debug(String.format("Created session: %s", session));
		return session;
	}
	
	private Session findSession(InetPoint source, AbstractData pdu) {
		SemiDialogID dialogID = null;
		GroupID groupID = null;
		TemporaryID requestID = null;
		SemiSequenceID seqID = null;
		boolean incrementCount = false;
		if ( pdu instanceof DataConfirmation ) {
			DataConfirmation dataConfirmation = (DataConfirmation)pdu;
			dialogID = dataConfirmation.getDialogID();
			seqID = dataConfirmation.getSeqID();
			groupID = dataConfirmation.getGroupID();
			requestID = dataConfirmation.getRequestID();
		} else if ( pdu instanceof DataAcceptance ) {
			DataAcceptance dataAcceptance = (DataAcceptance)pdu;
			dialogID = dataAcceptance.getDialogID();
			seqID = dataAcceptance.getSeqID();
			groupID = dataAcceptance.getGroupID();
			requestID = dataAcceptance.getRequestID();
		} else if ( pdu instanceof IntersectionSituationDataAcceptance ) {
			IntersectionSituationDataAcceptance dataAcceptance = (IntersectionSituationDataAcceptance)pdu;
			dialogID = dataAcceptance.getDialogID();
			seqID = dataAcceptance.getSeqID();
			groupID = dataAcceptance.getGroupID();
			requestID = dataAcceptance.getRequestID();
		} else if ( pdu instanceof IntersectionSituationData ) {
			IntersectionSituationData isd = (IntersectionSituationData)pdu;
			dialogID = isd.getDialogID();
			seqID = isd.getSeqID();
			groupID = isd.getGroupID();
			requestID = isd.getRequestID();
			incrementCount = true;
		} else if ( pdu instanceof AdvisorySituationData ) {
			AdvisorySituationData asd = (AdvisorySituationData)pdu;
			dialogID = asd.getDialogID();
			seqID = asd.getSeqID();
			groupID = asd.getGroupID();
			requestID = asd.getRequestID();		
		} else if ( pdu instanceof ObjectRegistrationData ) {
			ObjectRegistrationData ord = (ObjectRegistrationData)pdu;
			dialogID = ord.getDialogID();
			seqID = ord.getSeqID();
			groupID = ord.getGroupID();
			requestID = ord.getRequestID();		
		}
		if ( dialogID != null && requestID != null && groupID != null) {
			SessionKey sessionKey = new SessionKey(source, dialogID, groupID, requestID);
			log.debug(String.format("Searching for session: %s", sessionKey));
			Session session = sessions.get(sessionKey);
			if ( session != null && !session.isInactive() ) {
				if ( incrementCount )
					session.incrementCount();
				session.putSeqID(seqID);
				return session;
			}
		}
		return null;
	}
	
	private int calculateSessionTimeToLive(SemiDialogID dialogID) {
		// we have some special cases, for example, advSitDatDist dialog, where a session is created in the transport
		// but all traffic except for the data acceptance and final receipt happens outside of the transport, so in these special cases we 
		// have to allow for longer timeout to make sure that the session does not expire before the data acceptance UDP message
		// and JMS receipt from the data sink are received by the transport 
		return (dialogID != SemiDialogID.advSitDatDist && 
				dialogID != SemiDialogID.intersectionSitDataQuery && 
				dialogID != SemiDialogID.objDisc) ? sessionTimeToLive : 3*sessionTimeToLive;
	}
	
	private Session getMetaSession(InetPoint source, AbstractData pdu) {
		return getMetaSession(source, pdu, false);
	}
	
	private Session getMetaSession(InetPoint source, AbstractData pdu, boolean requireTrustEstablishemnt) {
		SemiDialogID dialogID = DialogIDHelper.getDialogID(pdu);
		Session metaSession = getMetaSession(source, dialogID);
		if ( metaSession != null && !metaSession.isInactive()  ) {
			metaSession.touch();
			return metaSession;
		}
		return requireTrustEstablishemnt ? null : new Session(new SessionKey(source, dialogID));
	}
	
	//
	// Meta Session and friends
	//
	
	private Session createMetaSession(ServiceRequest serviceRequest, InetPoint source, byte[] certificate, byte[] certID8) {
		// if meta session for this source and dialog type exist we remove it first by closing that session
		SessionKey sessionKey = new SessionKey(source, serviceRequest.getDialogID());
		Session session = sessions.get(sessionKey);
		if ( session != null )
			session.close();
		// create new meta session
		session = new Session(sessionKey, DEFAULT_META_SESSION_TTL);
		InetPoint destination = getDestination(serviceRequest, source);
		if ( destination != null )
			session.setDestination(destination);
		if ( certificate != null )
			session.setCertificate(certificate);
		if ( certID8 != null )
			session.setCertID8(certID8);
		String sessionID = session.getSessionID();
		sessions.put(sessionKey, session);
		sessions.put(sessionID,  session);
		return session;
	}
	
	private Session getMetaSession(InetPoint source, SemiDialogID dialogID) {
		Session metaSession = sessions.get(new SessionKey(source, dialogID));
		return metaSession != null && !metaSession.isInactive() ? metaSession  : null;
	}
	
	private InetPoint getDestination(ServiceRequest serviceRequest, InetPoint source) {
		assert(serviceRequest != null);
		assert(source != null);
		if ( !serviceRequest.hasDestination() ) 
			return null;
		ConnectionPoint destination = serviceRequest.getDestination();
		if ( destination == null )
			return null;
		byte[] address = null;
		if ( destination.hasAddress() ) {
			IpAddress ipAddress = destination.getAddress();
			if ( ipAddress != null ) {
				if ( ipAddress.hasIpv6Address() ) {
					IPv6Address ipV6Address = (IPv6Address)ipAddress.getChosenValue();
					if ( ipV6Address != null )
						address = ipV6Address.byteArrayValue();
				} else if ( ipAddress.hasIpv4Address() ) {
					IPv4Address ipV4Address = (IPv4Address)ipAddress.getChosenValue();
					if ( ipV4Address != null )
						address = ipV4Address.byteArrayValue();
				} else {
					log.warn(String.format("Service request contains destination that has address but the address is not IPv4 or IPv6. Using source as destination. Message: %s", serviceRequest));
					return null;
				}
			}
		}
		if ( address == null )
			address = source.address;
		assert(address != null );
		address = address.clone();
		return new InetPoint(address, (int)destination.getPort().longValue(), source.forward);
	}
	
	//
	// Session Purger
	//
	
	private Timer timer = null;
	
	private void startSessionPurger()
	{				
		if ( timer == null )
			timer = new Timer(true);
		
		TimerTask task = new TimerTask() {
			@Override
			public void run()
			{
				purgeSessions();
			}
		};
		timer.schedule(task, sessionPurgeInterval, sessionPurgeInterval);
	}
	
	private void stopSessionPurger()
	{
		if ( timer != null )
		{
			timer.cancel();
			timer.purge();
			timer = null;
		}
	}
	
	private void purgeSessions() {
		log.debug("Purging inactive sessions");
		for ( Entry<Object, Session> entry : sessions.entrySet() ) {
			if ( entry.getValue().isInactive() ) {
				Object key = entry.getKey();
				log.debug(String.format("Purging session with key: %s", key));
				sessions.remove(key);
			}
		}
	}

	//
	// Unit test helpers
	//
	
	int getSessionsCount() {
		return sessions.size()/2;	// two entries per session
	}
	
	Session getSession(SessionKey sessionKey) {
		return sessions.get(sessionKey);
	}
	
	void dumpSessions() {
		int i = 0;
		System.out.println("---------------- Sessions ----------------\n");
		for ( Entry<Object, Session> entry : sessions.entrySet() ) {
			System.out.printf("%3d: key: %s value: %s\n", i++, entry.getKey(), entry.getValue());
		}
		System.out.println("------------------------------------------\n");
	}
}

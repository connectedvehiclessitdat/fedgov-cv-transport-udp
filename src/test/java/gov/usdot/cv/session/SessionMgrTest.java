package gov.usdot.cv.session;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import gov.usdot.asn1.generated.j2735.semi.ConnectionPoint;
import gov.usdot.asn1.generated.j2735.semi.DataAcceptance;
import gov.usdot.asn1.generated.j2735.semi.DataRequest;
import gov.usdot.asn1.generated.j2735.semi.SemiDialogID;
import gov.usdot.asn1.generated.j2735.semi.ServiceRequest;
import gov.usdot.asn1.generated.j2735.semi.VehSitDataMessage;
import gov.usdot.asn1.j2735.CVSampleMessageBuilder;
import gov.usdot.cv.common.asn1.ConnectionPointHelper;
import gov.usdot.cv.common.asn1.GroupIDHelper;
import gov.usdot.cv.common.asn1.TemporaryIDHelper;
import gov.usdot.cv.common.inet.InetPoint;
import gov.usdot.cv.common.util.UnitTestHelper;

import org.junit.BeforeClass;
import org.junit.Test;

public class SessionMgrTest {
	static final private boolean isDebugOutput = false;

	@BeforeClass
	public static void init() {
		UnitTestHelper.initLog4j(isDebugOutput);
	}
	
	@Test
	public void testVehSitDataMessageNoTrust() throws InterruptedException, IOException {
		final int sessionTTL = 20*1000;
		final int purgeInt = 5*1000;
		SessionMgr mgr = new SessionMgr(sessionTTL, purgeInt);
		try {
			mgr.initialize();
			final byte[] address = InetAddress.getByName("127.0.0.1").getAddress();
			final int port = 47561;
			
			// Create data message
			VehSitDataMessage vhdm = CVSampleMessageBuilder.buildVehSitDataMessage();
			
			// Simulate receiving data message without trust establishment
			Session session = mgr.getSession(address, port, vhdm);
			assertNotNull(session);						// session is created
			assertNotNull(session.getSessionID());		// has valid session iD
			assertNotNull(session.getSessionKey());		// has valid session key
			assertNull(session.getDestination());		// does not have destination set
			assertNull(session.getCertificate());		// does not have certificate set
			// and is NOT persistent
			Session sessionOutByID = mgr.getSession(session.getSessionID());
			assertNull(sessionOutByID);
			Session sessionOutByKey = mgr.getSession(session.getSessionKey());
			assertNull(sessionOutByKey);
			
			// new session is created every time 
			Session session2 = mgr.getSession(address, port, vhdm);
			assertNotNull(session2);						// session is created
			assertNotNull(session2.getSessionID());		// has valid session iD
			assertNotNull(session2.getSessionKey());		// has valid session key
			assertNull(session2.getDestination());		// does not have destination set
			assertNull(session2.getCertificate());		// does not have certificate set
			// and is NOT persistent
			Session session2OutByID = mgr.getSession(session2.getSessionID());
			assertNull(session2OutByID);
			Session session2OutByKey = mgr.getSession(session2.getSessionKey());
			assertNull(session2OutByKey);
			// session and ID are different
			assertFalse(session.equals(session2));
			assertFalse(session.getSessionID().equals(session2.getSessionID()));
			// but the key is the same as it is based on source. This is not a problem because the session is not persistent
			assertTrue(session.getSessionKey().equals(session2.getSessionKey()));
		} finally {
			mgr.dispose();
		}
	}
	
	@Test
	public void testVehSitDataMessage() throws InterruptedException, IOException {
		final int sessionTTL = 20*1000;
		final int purgeInt = 5*1000;
		SessionMgr mgr = new SessionMgr(sessionTTL, purgeInt);
		try {
			mgr.initialize();
			final byte[] address = InetAddress.getByName("127.0.0.1").getAddress();
			final int port = 47561;
			
			// Create data message
			VehSitDataMessage vhdm = CVSampleMessageBuilder.buildVehSitDataMessage();
			
			// Simulate receiving service request without destination and certificate
			ServiceRequest svcRec = CVSampleMessageBuilder.buildServiceRequest(vhdm.getRequestID(), SemiDialogID.vehSitData);
			Session metaSession = mgr.getSession(address, port, svcRec);
			// Will create a valid session that is a meta session
			assertNotNull(metaSession);
			assertTrue(metaSession.getSessionKey().isMetaSession);
			// is persistent session that we can query for by ID or by Key
			Session metaSessionOutByID = mgr.getSession(metaSession.getSessionID());
			assertNotNull(metaSessionOutByID);
			assertEquals(metaSession, metaSessionOutByID);
			Session metaSessionOutByKey = mgr.getSession(metaSession.getSessionKey());
			assertNotNull(metaSessionOutByKey);
			assertEquals(metaSession, metaSessionOutByKey);
			
			// Simulate receiving data message after trust establishment
			Session session = mgr.getSession(address, port, vhdm);
			assertNotNull(session);						// session is created
			assertNotNull(session.getSessionID());		// has valid session iD
			assertNotNull(session.getSessionKey());		// has valid session key
			assertNull(session.getDestination());		// does not have destination set
			assertNull(session.getCertificate());		// does not have certificate set
			// is the meta session create during the trust establishment
			assertEquals(metaSession, session);
		} finally {
			mgr.dispose();
		}
	}
	
	@Test
	public void testVehSitDataMessageWithDestAndCert() throws InterruptedException, IOException {
		final int sessionTTL = 20*1000;
		final int purgeInt = 5*1000;
		SessionMgr mgr = new SessionMgr(sessionTTL, purgeInt);
		try {
			mgr.initialize();
			final byte[] address = InetAddress.getByName("127.0.0.1").getAddress();
			final int port = 47561;
			final String destAddress = "127.0.0.2";
			final int destPort = 47562;
			final byte[] certificate = "my certificate".getBytes();
			final byte[] certID8 = new byte[8];
			
			// Create data message
			VehSitDataMessage vhdm = CVSampleMessageBuilder.buildVehSitDataMessage();
			
			// Simulate receiving service request with destination and certificate
			ConnectionPoint destination = ConnectionPointHelper.createConnectionPoint(InetAddress.getByName(destAddress), destPort);
			ServiceRequest svcRec = CVSampleMessageBuilder.buildServiceRequest(vhdm.getRequestID(), SemiDialogID.vehSitData, destination);
			Session metaSession = mgr.getSession(address, port, svcRec, certificate, certID8);
			// Will create a valid session that is a meta session
			assertNotNull(metaSession);
			assertTrue(metaSession.getSessionKey().isMetaSession);
			// is persistent session that we can query for by ID or by Key
			Session metaSessionOutByID = mgr.getSession(metaSession.getSessionID());
			assertNotNull(metaSessionOutByID);
			assertEquals(metaSession, metaSessionOutByID);
			Session metaSessionOutByKey = mgr.getSession(metaSession.getSessionKey());
			assertNotNull(metaSessionOutByKey);
			assertEquals(metaSession, metaSessionOutByKey);
			
			// Simulate receiving data message after trust establishment
			Session session = mgr.getSession(address, port, vhdm);
			assertNotNull(session);						// session is created
			assertNotNull(session.getSessionID());		// has valid session iD
			assertNotNull(session.getSessionKey());		// has valid session key
			InetPoint destPoint = session.getDestination();
			assertNotNull(destPoint);					// has destination set
			assertEquals(destPoint.getInetAddress().getHostName(), destAddress);
			assertEquals(destPoint.port, destPort);
			byte[] certificateOut = session.getCertificate();
			assertNotNull(certificateOut);				// has certificate set
			assertArrayEquals(certificate,certificateOut);
			// is the meta session create during the trust establishment
			assertEquals(metaSession, session);
		} finally {
			mgr.dispose();
		}
	}

	@Test
	public void testAdvSitDatDistDialog() throws UnknownHostException, InterruptedException {
		final int sessionTTL = 20*1000;
		final int purgeInt = 5*1000;
		SessionMgr mgr = new SessionMgr(sessionTTL, purgeInt);
		try {
			mgr.initialize();
			final byte[] address = InetAddress.getByName("127.0.0.1").getAddress();
			final int port = 47561;
			
			// ServiceRequest
			DataRequest rasdr = CVSampleMessageBuilder.buildRSUAdvisorySitDataRequest();
			ServiceRequest svcRec = CVSampleMessageBuilder.buildServiceRequest(rasdr.getRequestID(), rasdr.getGroupID(), SemiDialogID.advSitDatDist);
			
			// is a meta session
			Session metaSession = mgr.getSession(address, port, svcRec);
			assertNotNull(metaSession);
			assertTrue(metaSession.getSessionKey().isMetaSession);
			
			// is persisted session
			Session metaSessionOutByID = mgr.getSession(metaSession.getSessionID());
			assertNotNull(metaSessionOutByID);
			assertEquals(metaSession, metaSessionOutByID);
			
			Session metaSessionOutByKey = mgr.getSession(metaSession.getSessionKey());
			assertNotNull(metaSessionOutByKey);
			assertEquals(metaSession, metaSessionOutByKey);
			
			assertEquals(1, mgr.getSessionsCount());	// one meta session is present
			
			// Simulate receiving RSUAdvisorySitDataRequest message
			Session session = mgr.getSession(address, port, rasdr);
			// new session -- ID is different and it's not a meta session
			assertNotNull(session);
			assertFalse(metaSession.getSessionID().equals(session.getSessionID()));
			SessionKey sessionKey = session.getSessionKey();
			assertNotNull(sessionKey);
			assertFalse(sessionKey.isMetaSession);
			if ( isDebugOutput )
				System.out.println("Key : " + sessionKey);
			// session is persisted
			Session sessionOutByID = mgr.getSession(session.getSessionID());
			assertNotNull(sessionOutByID);
			assertEquals(session, sessionOutByID);
			Session sessionOutByKey = mgr.getSession(session.getSessionKey());
			assertNotNull(sessionOutByKey);
			assertEquals(session, sessionOutByKey);
			
			assertEquals(2, mgr.getSessionsCount());	// one session and one meta session

			// Test hashCode functionality to make sure that sessions with identical keys match
			InetPoint source = new InetPoint(sessionKey.source.address, sessionKey.source.port, sessionKey.source.forward);
			SessionKey sessionKey2 = new SessionKey(source, SemiDialogID.valueOf(sessionKey.dialogID), GroupIDHelper.toGroupID(0), TemporaryIDHelper.toTemporaryID(sessionKey.requestID));
			if ( isDebugOutput )
				System.out.println("Key2: " + sessionKey2);
			assertEquals(sessionKey.hashCode, sessionKey2.hashCode);
	
			source = new InetPoint(sessionKey.source.address.clone(), sessionKey.source.port, sessionKey.source.forward);
			SessionKey sessionKey3 = new SessionKey(source, SemiDialogID.valueOf(sessionKey.dialogID), GroupIDHelper.toGroupID(0), TemporaryIDHelper.toTemporaryID(sessionKey.requestID));
			if ( isDebugOutput )
				System.out.println("Key3: " + sessionKey3);
			assertEquals(sessionKey.hashCode, sessionKey3.hashCode);
			
			if ( isDebugOutput )
				mgr.dumpSessions();

			// message within session that is not a meta session
			DataAcceptance asdba = CVSampleMessageBuilder.buildDataAcceptance(SemiDialogID.advSitDatDist);
			Session session2 = mgr.getSession(address, port, asdba);
			assertEquals(session.getSessionID(), session2.getSessionID());
			
			assertEquals(2, mgr.getSessionsCount());	// one session and one meta session
			
			// expiration
			assertEquals(2, mgr.getSessionsCount());	// one session and one meta session
			Thread.sleep(sessionTTL + purgeInt + 1000);
			metaSession.touch();						// keep meta session from expiring just yet
			Thread.sleep(sessionTTL*2 + purgeInt + 1000);
			assertEquals(1, mgr.getSessionsCount());	// only meta session remains
			
			// no sessions -- session expired
			session2 = mgr.getSession(session.getSessionID());
			assertNull(session2);
			
			// no session -- message is not a session starting message
			session2 = mgr.getSession(address, port, asdba);
			assertNull(session2);
			
			// new session -- the new session ID is different from the previous session ID
			session2 = mgr.getSession(address, port, rasdr);
			assertNotNull(session2);
			assertFalse(session.getSessionID().equals(session2.getSessionID()));
			
			assertEquals(2, mgr.getSessionsCount());	// one session and one meta session

			// close session
			assertFalse(session2.isClosed());
			assertFalse(session2.isExpired());
			assertFalse(session2.isInactive());
			session2.close();
			assertTrue(session2.isClosed());
			assertFalse(session2.isExpired());
			assertTrue(session2.isInactive());
			
			// closed session expiration
			assertEquals(2, mgr.getSessionsCount());	// one session and one meta session
			Thread.sleep(purgeInt + 1000);
			assertEquals(1, mgr.getSessionsCount());	// one meta session
			
			if ( isDebugOutput ) {						// this adds significant time to the unit test
				// meta session expiration -- keep alive won't let it expire because it's being used
				Thread.sleep(SessionMgr.DEFAULT_META_SESSION_TTL - purgeInt + 1000);
				assertEquals(1, mgr.getSessionsCount());	// one meta session
				
				// but now the session expires and is purged...
				Thread.sleep(SessionMgr.DEFAULT_META_SESSION_TTL - purgeInt + 1000);
				assertEquals(0, mgr.getSessionsCount());	// no sessions
			}
		} finally {
			mgr.dispose();
		}
	}
}

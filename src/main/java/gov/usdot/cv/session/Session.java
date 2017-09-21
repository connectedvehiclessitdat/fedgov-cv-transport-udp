package gov.usdot.cv.session;

import gov.usdot.asn1.generated.j2735.semi.SemiSequenceID;
import gov.usdot.cv.common.inet.InetPoint;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.log4j.Logger;

public class Session {
	
	protected static final Logger log = Logger.getLogger(Session.class);
	
	private final SessionKey sessionKey;
	private final String sessionID;
	private final long maxIdleTimeToLive;
	private long lastActiveTime;
	private boolean closed = false;
	private AtomicInteger count = new AtomicInteger(0);
	
	private InetPoint destination = null;
	private byte[] certificate = null;
	private byte[] certID8 = null;

	List<SemiSequenceID> seqIDs = Collections.synchronizedList(new ArrayList<SemiSequenceID>());
	
	public Session(SessionKey sessionKey) {
		this(sessionKey, Long.MAX_VALUE);
	}
	
	public Session(SessionKey sessionKey, long maxIdleTimeToLive) {
		this.sessionKey = sessionKey;
		this.maxIdleTimeToLive = maxIdleTimeToLive;
		this.sessionID = UUID.randomUUID().toString();
		touch();
	}
	
	public final String getSessionID() {
		return sessionID;
	}
	
	public final SessionKey getSessionKey() {
		return sessionKey;
	}
	
	public void touch() {
		this.lastActiveTime = System.currentTimeMillis();
	}
	
	public synchronized boolean isInactive() {
		return isClosed() || isExpired();
	}
	
	public boolean isExpired() {
		return System.currentTimeMillis() - lastActiveTime > maxIdleTimeToLive;
	}
	
	public void putSeqID(SemiSequenceID seqID) {
		touch();
		seqIDs.add(seqID);
		if ( !isInactive() && seqID == SemiSequenceID.accept )
			SessionReceiptReceiver.wakeUpWorker();
	}
	
	public boolean hasSeqID(SemiSequenceID seqID) {
		return seqIDs.contains(seqID);
	}
	
	public boolean isClosed() {
		return closed;
	}

	public void close() {
		closed = true;
	}
	
	public void incrementCount() {
		count.incrementAndGet();
	}
	
	public void resetCount() {
		count.set(0);
	}
	
	public int getCount() {
		return count.get();
	}
	
	@Override
	public String toString() {
		return String.format("%s { source = %s; sessionID = %s; count = %d; lastActiveTime = %d (TTL: %d); closed = %s }",
				getClass().getSimpleName(),
				sessionKey,
				sessionID,
				count.get(),
				lastActiveTime, maxIdleTimeToLive - (System.currentTimeMillis() - lastActiveTime),
				closed ? "true" : "false"
				);
	}

	public InetPoint getDestination() {
		return destination;
	}
	
	public void setDestination(InetPoint destination) {
		this.destination = destination;
	}
	
	public byte[] getCertificate() {
		return certificate;
	}

	public void setCertificate(byte[] certificate) {
		this.certificate = certificate;
	}
	
	public byte[] getCertID8() {
		return certID8;
	}

	public void setCertID8(byte[] certID8) {
		this.certID8 = certID8;
	}

}

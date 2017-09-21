package gov.usdot.cv.session;

import java.util.Arrays;

import gov.usdot.asn1.generated.j2735.dsrc.TemporaryID;
import gov.usdot.asn1.generated.j2735.semi.GroupID;
import gov.usdot.asn1.generated.j2735.semi.SemiDialogID;
import gov.usdot.cv.common.asn1.GroupIDHelper;
import gov.usdot.cv.common.asn1.TemporaryIDHelper;
import gov.usdot.cv.common.inet.InetPoint;

public class SessionKey {
	public final InetPoint source;
	public final long dialogID;
	public final int groupID;
	public final int requestID;
	public final int hashCode;
	public final boolean isMetaSession; 
	
	public SessionKey(InetPoint source, SemiDialogID dialogID) {
		this(source, dialogID, GroupIDHelper.toGroupID(0), TemporaryIDHelper.toTemporaryID(0), true);
	}
	
	public SessionKey(InetPoint source, SemiDialogID dialogID, GroupID groupID, TemporaryID requestID) {
		this(source, dialogID, groupID, requestID, false);
	}
	
	protected SessionKey(InetPoint source, SemiDialogID dialogID, GroupID groupID, TemporaryID requestID, boolean isMetaSession) {
		this.source = source;
		this.dialogID = dialogID.longValue();
		this.groupID = TemporaryIDHelper.fromTemporaryID(groupID);
		this.requestID = TemporaryIDHelper.fromTemporaryID(requestID);
		this.isMetaSession = isMetaSession;
		this.hashCode = getHashCode();
	}

	@Override
	public int hashCode() {
		return hashCode;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		final SessionKey other = (SessionKey) obj;
		if (requestID != other.requestID || groupID != other.groupID || dialogID != other.dialogID || isMetaSession != other.isMetaSession)
			return false;
		if (source == null && other.source == null) 
			return true;
		if (source == null || other.source == null )
			return false;
		if ( source.port != other.source.port )
			return false;
		if ( source.forward != other.source.forward )
			return false;
		if ( source.address == null && other.source.address == null)
			return true;
		if ( source.address == null || other.source.address == null)
			return false;
		return Arrays.equals(source.address, other.source.address);
	}
	
	@Override
	public String toString() {
		return String.format("%s { source = %s; dialogID = %d (0x%x); groupID = %d (0x%x); requestID = %d (0x%x); isMetaSession = %s; hashCode = 0x%x }",
				getClass().getSimpleName(),
				source != null ? source : "<null>",
				dialogID, dialogID,
				groupID, groupID,
				requestID, requestID,
				isMetaSession ? "true" : "false",
				hashCode
				);
	}
	
	private int getHashCode() {
		return Arrays.deepHashCode(	new Object[] {
				source != null ? source.port : 0,
				source != null ? source.forward : 0,
				source != null ? source.address : new byte[0],
				dialogID,
				groupID,
				requestID,
				isMetaSession,
		});
	}
	
}

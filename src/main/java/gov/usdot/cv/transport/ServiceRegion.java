package gov.usdot.cv.transport;

import gov.usdot.asn1.j2735.J2735Util;

public class ServiceRegion {
	
	static final double DEFALUT_NW_CNR_LATITUDE  =  43.0;
	static final double DEFALUT_NW_CNR_LONGITUDE = -85.0;
	static final double DEFALUT_SE_CNR_LATITUDE  =  41.0;
	static final double DEFALUT_SE_CNR_LONGITUDE = -82.0;
	
	ServiceRegion() {
		this(DEFALUT_NW_CNR_LATITUDE,DEFALUT_NW_CNR_LONGITUDE,DEFALUT_SE_CNR_LATITUDE,DEFALUT_SE_CNR_LONGITUDE);
	}
	
	public ServiceRegion(double nwCnr_Latitude, double nwCnr_Longitude, double seCnr_Latitude, double seCnr_Longitude) {
		this.nwCnr_Latitude  = J2735Util.convertGeoCoordinateToInt(nwCnr_Latitude);
		this.nwCnr_Longitude = J2735Util.convertGeoCoordinateToInt(nwCnr_Longitude);
		this.seCnr_Latitude  = J2735Util.convertGeoCoordinateToInt(seCnr_Latitude);
		this.seCnr_Longitude = J2735Util.convertGeoCoordinateToInt(seCnr_Longitude);		
	}

	public final int nwCnr_Latitude;
	public final int nwCnr_Longitude;
	public final int seCnr_Latitude;
	public final int seCnr_Longitude;
}

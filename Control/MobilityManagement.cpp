/**@file GSM/SIP Mobility Management, GSM 04.08. */
/*
* Copyright 2008, 2009, 2010, 2011 Free Software Foundation, Inc.
* Copyright 2011 Range Networks, Inc.
*
* This software is distributed under the terms of the GNU Affero Public License.
* See the COPYING file in the main directory for details.
*
* This use of this software may be subject to additional restrictions.
* See the LEGAL file in the main directory for details.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/


#include <Timeval.h>

#include "ControlCommon.h"
#include "MobilityManagement.h"
#include "SMSControl.h"
#include "CallControl.h"
#include "RRLPServer.h"

#include <GSMLogicalChannel.h>
#include <GSML3RRMessages.h>
#include <GSML3MMMessages.h>
#include <GSML3CCMessages.h>
#include <GSMConfig.h>

using namespace std;

#include <SIPInterface.h>
#include <SIPUtility.h>
#include <SIPMessage.h>
#include <SIPEngine.h>
#include <SubscriberRegistry.h>

using namespace SIP;

#include <Regexp.h>
#include <Reporting.h>
#include <Logger.h>
#undef WARNING


using namespace GSM;
using namespace Control;


/** Controller for CM Service requests, dispatches out to multiple possible transaction controllers. */
void Control::CMServiceResponder(const L3CMServiceRequest* cmsrq, LogicalChannel* DCCH)
{
	assert(cmsrq);
	assert(DCCH);
	LOG(INFO) << *cmsrq;
	switch (cmsrq->serviceType().type()) {
		case L3CMServiceType::MobileOriginatedCall:
			gReports.incr("OpenBTS.GSM.MM.CMServiceRequest.MOC");
			MOCStarter(cmsrq,DCCH);
			break;
		case L3CMServiceType::ShortMessage:
			gReports.incr("OpenBTS.GSM.MM.CMServiceRequest.MOSMS");
			MOSMSController(cmsrq,DCCH);
			break;
		default:
			gReports.incr("OpenBTS.GSM.MM.CMServiceRequest.Unhandled");
			LOG(NOTICE) << "service not supported for " << *cmsrq;
			// Cause 0x20 means "serivce not supported".
			DCCH->send(L3CMServiceReject(0x20));
			DCCH->send(L3ChannelRelease());
	}
	// The transaction may or may not be cleared,
	// depending on the assignment type.
}




/** Controller for the IMSI Detach transaction, GSM 04.08 4.3.4. */
void Control::IMSIDetachController(const L3IMSIDetachIndication* idi, LogicalChannel* DCCH)
{
	assert(idi);
	assert(DCCH);
	LOG(INFO) << *idi;

	// The IMSI detach maps to a SIP unregister with the local Asterisk server.
	try { 
		// FIXME -- Resolve TMSIs to IMSIs.
		if (idi->mobileID().type()==IMSIType) {
			SIPEngine engine(gConfig.getStr("SIP.Proxy.Registration").c_str(), idi->mobileID().digits());
			AuthenticationParameters authParams(idi->mobileID());
			engine.unregister(authParams);
		}
	}
	catch(SIPTimeout) {
		LOG(ALERT) "SIP registration timed out.  Is Asterisk running?";
	}
	// No reponse required, so just close the channel.
	DCCH->send(L3ChannelRelease());
	// Many handsets never complete the transaction.
	// So force a shutdown of the channel.
	DCCH->send(HARDRELEASE);
}




/**
	Send a given welcome message from a given short code.
	@return true if it was sent
*/
bool sendWelcomeMessage(const char* messageName, const char* shortCodeName, const char *IMSI, LogicalChannel* DCCH, const char *whiteListCode = NULL)
{
	if (!gConfig.defines(messageName)) return false;
	LOG(INFO) << "sending " << messageName << " message to handset";
	ostringstream message;
	message << gConfig.getStr(messageName) << " IMSI:" << IMSI;
	if (whiteListCode) {
		message << ", white-list code: " << whiteListCode;
	}
	// This returns when delivery is acked in L3.
	deliverSMSToMS(
		gConfig.getStr(shortCodeName).c_str(),
		message.str().c_str(), "text/plain",
		random()%7,DCCH);
	return true;
}

/**
	Controller for the Location Updating transaction, GSM 04.08 4.4.4.
	@param lur The location updating request.
	@param DCCH The Dm channel to the MS, which will be released by the function.
*/
void Control::LocationUpdatingController(const L3LocationUpdatingRequest* lur, LogicalChannel* DCCH)
{
	assert(DCCH);
	assert(lur);
	LOG(INFO) << *lur;

	// The location updating request gets mapped to a SIP
	// registration with the SIP registrar.

	// We also allocate a new TMSI for every handset we encounter.
	// If the handset is allowed to register it may receive a TMSI reassignment.
	gReports.incr("OpenBTS.GSM.MM.LUR.Start");

	// Resolve an IMSI and see if there's a pre-existing IMSI-TMSI mapping.
	// This operation will throw an exception, caught in a higher scope,
	// if it fails in the GSM domain.
	L3MobileIdentity mobileID = lur->mobileID();
	bool sameLAI = (lur->LAI() == gBTS.LAI());
	unsigned preexistingTMSI = resolveIMSI(sameLAI,mobileID,DCCH);
	const char *IMSI = mobileID.digits();
	// IMSIAttach set to true if this is a new registration.
	bool IMSIAttach = (preexistingTMSI==0);

	// We assign generate a TMSI for every new phone we see,
	// even if we don't actually assign it.
	unsigned newTMSI = 0;
	if (!preexistingTMSI) newTMSI = gTMSITable.assign(IMSI,lur);

	// Try to register the IMSI.
	// This will be set true if registration succeeded in the SIP world.
	bool success = false;
	AuthenticationParameters authParams(mobileID);
	success = registerIMSI(authParams, DCCH);
	
	if (success && (gConfig.getNum("GSM.Encryption")))
	{
		success = authenticate(authParams, DCCH);
	}

	// This allows us to configure Open Registration
	bool openRegistration = false;
	if (gConfig.defines("Control.LUR.OpenRegistration")) {
		if (!gConfig.defines("Control.LUR.OpenRegistration.Message")) {
			gConfig.set("Control.LUR.OpenRegistration.Message","Welcome to the test network.  Your IMSI is ");
		}
		Regexp rxp(gConfig.getStr("Control.LUR.OpenRegistration").c_str());
		openRegistration = rxp.match(IMSI);
		if (gConfig.defines("Control.LUR.OpenRegistration.Reject")) {
			Regexp rxpReject(gConfig.getStr("Control.LUR.OpenRegistration.Reject").c_str());
			bool openRegistrationReject = rxpReject.match(IMSI);
			openRegistration = openRegistration && !openRegistrationReject;
		}
	}

	// Query for IMEI?
	if (gConfig.defines("Control.LUR.QueryIMEI")) {
		DCCH->send(L3IdentityRequest(IMEIType));
		L3Message* msg = getMessage(DCCH);
		L3IdentityResponse *resp = dynamic_cast<L3IdentityResponse*>(msg);
		if (!resp) {
			if (msg) {
				LOG(WARNING) << "Unexpected message " << *msg;
				delete msg;
			}
			throw UnexpectedMessage();
		}
		LOG(INFO) << *resp;
		string new_imei = resp->mobileID().digits();
		if (!gTMSITable.IMEI(IMSI,new_imei.c_str())){
			LOG(WARNING) << "failed access to TMSITable";
		} 

		//query subscriber registry for old imei, update if neccessary
		string name = string("IMSI") + IMSI;
		string old_imei = gSubscriberRegistry.imsiGet(name, "hardware");
		
		//if we have a new imei and either there's no old one, or it is different...
		if (!new_imei.empty() && (old_imei.empty() || old_imei != new_imei)){
			LOG(INFO) << "Updating IMSI" << IMSI << " to IMEI:" << new_imei;
			if (gSubscriberRegistry.imsiSet(name,"RRLPSupported", "1")) {
			 	LOG(INFO) << "SR RRLPSupported update problem";
			}
			if (gSubscriberRegistry.imsiSet(name,"hardware", new_imei)) {
				LOG(INFO) << "SR hardware update problem";
			}
		}
		delete msg;
	}

	// Query for classmark?
	if (IMSIAttach && gConfig.defines("Control.LUR.QueryClassmark")) {
		DCCH->send(L3ClassmarkEnquiry());
		L3Message* msg = getMessage(DCCH);
		L3ClassmarkChange *resp = dynamic_cast<L3ClassmarkChange*>(msg);
		if (!resp) {
			if (msg) {
				LOG(WARNING) << "Unexpected message " << *msg;
				delete msg;
			}
			throw UnexpectedMessage();
		}
		LOG(INFO) << *resp;
		const L3MobileStationClassmark2& classmark = resp->classmark();
		if (!gTMSITable.classmark(IMSI,classmark))
			LOG(WARNING) << "failed access to TMSITable";
		delete msg;
	}

	// We fail closed unless we're configured otherwise
	if (!success && !openRegistration) {
		LOG(INFO) << "registration FAILED: " << mobileID;
		DCCH->send(L3LocationUpdatingReject(gConfig.getNum("Control.LUR.UnprovisionedRejectCause")));
		if (!preexistingTMSI) {
			sendWelcomeMessage( "Control.LUR.FailedRegistration.Message",
				"Control.LUR.FailedRegistration.ShortCode", IMSI,DCCH);
		}
		// Release the channel and return.
		DCCH->send(L3ChannelRelease());
		return;
	}

	// If success is true, we had a normal registration.
	// Otherwise, we are here because of open registration.
	// Either way, we're going to register a phone if we arrive here.

	if (success) {
		LOG(INFO) << "registration SUCCESS: " << mobileID;
	} else {
		LOG(INFO) << "registration ALLOWED: " << mobileID;
	}


	// Send the "short name" and time-of-day.
	if (IMSIAttach && gConfig.defines("GSM.Identity.ShortName")) {
		DCCH->send(L3MMInformation(gConfig.getStr("GSM.Identity.ShortName").c_str()));
	}
	// Accept. Make a TMSI assignment, too, if needed.
	if (preexistingTMSI || !gConfig.defines("Control.LUR.SendTMSIs")) {
		DCCH->send(L3LocationUpdatingAccept(gBTS.LAI()));
	} else {
		assert(newTMSI);
		DCCH->send(L3LocationUpdatingAccept(gBTS.LAI(),newTMSI));
		// Wait for MM TMSI REALLOCATION COMPLETE (0x055b).
		L3Frame* resp = DCCH->recv(1000);
		// FIXME -- Actually check the response type.
		if (!resp) {
			LOG(NOTICE) << "no response to TMSI assignment";
		} else {
			LOG(INFO) << *resp;
		}
		delete resp;
	}

	if (gConfig.defines("Control.LUR.QueryRRLP")) {
		// Query for RRLP
		if (!sendRRLP(mobileID, DCCH)) {
			LOG(INFO) << "RRLP request failed";
		}
	}

	// If this is an IMSI attach, send a welcome message.
	if (IMSIAttach) {
		if (success) {
			sendWelcomeMessage( "Control.LUR.NormalRegistration.Message",
				"Control.LUR.NormalRegistration.ShortCode", IMSI, DCCH);
		} else {
			sendWelcomeMessage( "Control.LUR.OpenRegistration.Message",
				"Control.LUR.OpenRegistration.ShortCode", IMSI, DCCH);
		}
	}

	// Release the channel and return.
	DCCH->send(L3ChannelRelease());
	return;
}

bool Control::registerIMSI(Control::AuthenticationParameters& authParams, GSM::LogicalChannel* LCH)
{
	// Try to register the IMSI.
	// This will be set true if registration succeeded in the SIP world.
	try {
		SIPEngine engine(gConfig.getStr("SIP.Proxy.Registration").c_str(),authParams.mobileID().digits());
		LOG(DEBUG) << "waiting for registration of " << authParams.mobileID() << " on " << gConfig.getStr("SIP.Proxy.Registration");
		return engine.Register(SIPEngine::SIPRegister, authParams); 
	}
	catch(SIPTimeout) {
		LOG(ALERT) << "SIP registration timed out.  Is the proxy running at " << gConfig.getStr("SIP.Proxy.Registration");
		// Reject with a "network failure" cause code, 0x11.
		LCH->send(L3LocationUpdatingReject(0x11));
		gReports.incr("OpenBTS.GSM.MM.LUR.Timeout");
		// HACK -- wait long enough for a response
		// FIXME -- Why are we doing this?
		sleep(4);
		// Release the channel and return.
		LCH->send(L3ChannelRelease());
		return false;
	}
}

bool Control::authenticate (AuthenticationParameters& authParams, GSM::LogicalChannel* LCH)
{
	bool success = false;
	// Did we get a RAND for challenge-response?
	if (authParams.isRANDset()) {
		// Request the mobile's SRES.
		LCH->send(L3AuthenticationRequest(authParams.CKSN(), authParams.RAND()));
		LOG(DEBUG) << "SEND L3AuthenticationResponse " << L3AuthenticationRequest(authParams.CKSN(), authParams.RAND());
		L3Message* msg = getMessage(LCH);
		L3AuthenticationResponse *resp = dynamic_cast<L3AuthenticationResponse*>(msg);
		if (!resp) {
			if (msg) {
				LOG(DEBUG) << "Wait L3AuthenticationResponse, but Unexpected message " << *msg;
				delete msg;
			}
			// FIXME -- We should differentiate between wrong message and no message at all.
			throw UnexpectedMessage();
		}
		authParams.SRES((resp->SRES()).value());
		LOG(DEBUG) << "Recieve L3AuthenticationResponse "<<*resp;
		delete msg;
		
		// verify SRES
		if (registerIMSI(authParams, LCH)) {
			if (authParams.isKCset()) {
				LCH->setKc(authParams.KCstr().c_str());
				LOG(DEBUG) << "Ciphering key set for LCH , KC = " << authParams.KCstr().c_str();
				LCH->send(GSM::L3CipheringModeCommand(1)); // FIXME: use actual a5/#
				LCH->activateDecryption();
				LOG(DEBUG) << "Decryption activated: Ciphering Mode Command sent over " << LCH->type();
				L3Message* mc_msg = getMessage(LCH);
				L3CipheringModeComplete *mode_compl = dynamic_cast<L3CipheringModeComplete*>(mc_msg);
				if(!mode_compl) {
					if (mc_msg) {
						LOG(DEBUG) << "Wait L3CipheringModeComplet, but Unexpected message " << *msg;
						delete mc_msg;
					}
					// FIXME -- We should differentiate between wrong message and no message at all.
					throw UnexpectedMessage();
				}
				else {
					LOG(DEBUG) << *mode_compl << "Responce received, activating encryption.";
					LCH->activateEncryption();
					delete mc_msg;
					LOG(DEBUG) << "Authenticate success for" << authParams.mobileID();
					success = true;
				}
			}
		}
		else {
			LOG(DEBUG) << "Failed to verify SRES";
		}
	}
	else {
		LOG(DEBUG) << "Failed to obtain RAND";
	}
	return success;
}

void AuthenticationParameters::RANDstr(string strRAND)
{
	uint64_t hRAND;
	uint64_t lRAND;
	assert(strRAND.size() == 32);
	string strhRAND = strRAND.substr(0, 16);
	string strlRAND = strRAND.substr(16, 16);
	stringstream ssh;
	ssh << hex << strhRAND;
	ssh >> hRAND;
	stringstream ssl;
	ssl << hex << strlRAND;
	ssl >> lRAND;
	mRAND.RUpper(hRAND);
	mRAND.RLower(lRAND);
	mRANDset = true;
}

void AuthenticationParameters::KCstr(string strKC)
{
	assert(strKC.size() == 16);
	stringstream ssh;
	ssh << hex << strKC;
	ssh >> mKC;
	mKCset = true;
}

string AuthenticationParameters::SRESstr() const
{
	ostringstream os1;
	os1.width(8);
	os1.fill('0');
	os1 << hex << mSRES.value();
	return os1.str();
}

string AuthenticationParameters::RANDstr() const
{
	ostringstream os1;
	os1.width(16);
	os1.fill('0');
	os1 << hex << mRAND.RUpper();
	ostringstream os2;
	os2.width(16);
	os2.fill('0');
	os2 << hex << mRAND.RLower();
	ostringstream os3;
	os3 << os1.str() << os2.str();
	return os3.str();
}

string AuthenticationParameters::KCstr() const
{
	ostringstream os1;
	os1.width(16);
	os1.fill('0');
	os1 << hex << mKC;
	return os1.str();
}


// vim: ts=4 sw=4

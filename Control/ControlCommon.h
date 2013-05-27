/**@file Declarations for common-use control-layer functions. */
/*
* Copyright 2008-2011 Free Software Foundation, Inc.
* Copyright 2010 Kestrel Signal Processing, Inc.
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



#ifndef CONTROLCOMMON_H
#define CONTROLCOMMON_H


#include <stdio.h>
#include <list>

#include <Logger.h>
#include <Interthread.h>
#include <Timeval.h>


#include <GSML3CommonElements.h>
#include <GSML3MMElements.h>
#include <GSML3CCElements.h>
#include <GSML3RRMessages.h>
#include <SIPEngine.h>

#include "TMSITable.h"


// Enough forward refs to prevent "kitchen sick" includes and circularity.

namespace GSM {
class L3Message;
class LogicalChannel;
class SDCCHLogicalChannel;
class SACCHLogicalChannel;
class TCHFACCHLogicalChannel;
class L3CMServiceRequest;
};


/**@namespace Control This namepace is for use by the control layer. */
namespace Control {

class TransactionEntry;
class TransactionTable;

enum a3a8 { MILENAGE, COMP128v1 };

class AuthenticationParameters {

	private:
	GSM::L3MobileIdentity mMobileID;
	GSM::L3SRES mSRES;
	GSM::L3RAND mRAND;
	GSM::L3CipheringKeySequenceNumber mCKSN;
	string mKC;
	bool mRANDset;
	bool mKCset;
	bool mSRESset;
	enum a3a8 mAlg;
	unsigned a5;

	public:

	AuthenticationParameters(GSM::L3MobileIdentity wMobileID)
	    :mMobileID(wMobileID),
	    mSRES(0),
	    mRAND(0,0),
	    mCKSN(0),
	    mKC(""),
	    mRANDset(false),
	    mKCset(false),
	    mSRESset(false),
	    mAlg(COMP128v1),
	    a5(0)
	{}

	void set_CKSN(unsigned wCKSN) { mCKSN = GSM::L3CipheringKeySequenceNumber(wCKSN); }
	void set_SRES(uint32_t wSRES) { mSRES = GSM::L3SRES(wSRES); mSRESset = true; }
	void set_alg(enum a3a8 a) { mAlg = a; }
	enum a3a8 get_alg() { return mAlg; }
	void set_a5(unsigned alg) { a5 = alg; }
	unsigned get_a5() { return a5; }

	const char * get_RAND() const;
	void set_RAND(string RAND);
	const char * get_Kc() const { return mKC.c_str(); }
	void set_Kc(string key) { mKC = key; mKCset = true; }
	const char * get_SRES() const;

	const GSM::L3RAND& RAND() const { return mRAND; }
	const GSM::L3CipheringKeySequenceNumber& CKSN() const { return mCKSN; }
	const GSM::L3MobileIdentity& mobileID() const { return mMobileID; }
	const GSM::L3SRES SRES() const { return mSRES; }

	bool isRANDset() { return mRANDset; }
	bool isSRESset() { return mSRESset; }
	bool isKCset() { return mKCset; }
};
/**@name Call control time-out values (in ms) from ITU-T Q.931 Table 9-1 and GSM 04.08 Table 11.4. */
//@{
#ifndef RACETEST
const unsigned T301ms=60000;		///< recv ALERT --> recv CONN
const unsigned T302ms=12000;		///< send SETUP ACK --> any progress
const unsigned T303ms=10000;		///< send SETUP --> recv CALL CONF or REL COMP
const unsigned T304ms=20000;		///< recv SETUP ACK --> any progress
const unsigned T305ms=30000;		///< send DISC --> recv REL or DISC
const unsigned T308ms=30000;		///< send REL --> rev REL or REL COMP
const unsigned T310ms=30000;		///< recv CALL CONF --> recv ALERT, CONN, or DISC
const unsigned T313ms=30000;		///< send CONNECT --> recv CONNECT ACK
#else
// These are reduced values to force testing of poor network behavior.
const unsigned T301ms=18000;		///< recv ALERT --> recv CONN
const unsigned T302ms=1200;		///< send SETUP ACK --> any progress
const unsigned T303ms=400;			///< send SETUP --> recv CALL CONF or REL COMP
const unsigned T304ms=2000;		///< recv SETUP ACK --> any progress
const unsigned T305ms=3000;		///< send DISC --> recv REL or DISC
const unsigned T308ms=3000;		///< send REL --> rev REL or REL COMP
const unsigned T310ms=3000;		///< recv CALL CONF --> recv ALERT, CONN, or DISC
const unsigned T313ms=3000;		///< send CONNECT --> recv CONNECT ACK
#endif
//@}




/**@name Common-use functions from the control layer. */
//@{

/**
	Get a message from a LogicalChannel.
	Close the channel with abnormal release on timeout.
	Caller must delete the returned pointer.
	Throws ChannelReadTimeout, UnexpecedPrimitive or UnsupportedMessage on timeout.
	@param LCH The channel to receive on.
	@param SAPI The service access point.
	@return Pointer to message.
*/
// FIXME -- This needs an adjustable timeout.
GSM::L3Message* getMessage(GSM::LogicalChannel* LCH, unsigned SAPI=0);


//@}


/**@name Dispatch controllers for specific channel types. */
//@{
void FACCHDispatcher(GSM::TCHFACCHLogicalChannel *TCHFACCH);
void SDCCHDispatcher(GSM::SDCCHLogicalChannel *SDCCH);
void DCCHDispatcher(GSM::LogicalChannel *DCCH);
//@}



/**
	Resolve a mobile ID to an IMSI.
	Returns TMSI, if it is already in the TMSITable.
	@param sameLAI True if the mobileID is known to have come from this LAI.
	@param mobID A mobile ID, that may be modified by the function.
	@param LCH The Dm channel to the mobile.
	@return A TMSI value from the TMSITable or zero if none found.
*/
unsigned  resolveIMSI(bool sameLAI, GSM::L3MobileIdentity& mobID, GSM::LogicalChannel* LCH);

/**
	Resolve a mobile ID to an IMSI.
	@param mobID A mobile ID, that may be modified by the function.
	@param LCH The Dm channel to the mobile.
*/
void  resolveIMSI(GSM::L3MobileIdentity& mobID, GSM::LogicalChannel* LCH);


// Try to authenticate mobID using given channel
// Return 0 on success, error code otherwise:
// 1 - SIP timeout and no fallback configured
// 2 - SIP authentication rejected
// 3 - error inside authentication routine
unsigned attemptAuth(GSM::L3MobileIdentity mobID, GSM::LogicalChannel* LCH);

/**@name Control-layer exceptions. */
//@{

/**
	A control layer excpection includes a pointer to a transaction.
	The transaction might require some clean-up action, depending on the exception.
*/
class ControlLayerException {

	private:

	unsigned mTransactionID;

	public:

	ControlLayerException(unsigned wTransactionID=0)
		:mTransactionID(wTransactionID)
	{}

	unsigned transactionID() { return mTransactionID; }
};

/** Thrown when the control layer gets the wrong message */
class UnexpectedMessage : public ControlLayerException {
	public:
	UnexpectedMessage(unsigned wTransactionID=0)
		:ControlLayerException(wTransactionID)
	{}
};

/** Thrown when recvL3 returns NULL */
class ChannelReadTimeout : public ControlLayerException {
	public:
	ChannelReadTimeout(unsigned wTransactionID=0)
		:ControlLayerException(wTransactionID)
	{}
};

/** Thrown when L3 can't parse an incoming message */
class UnsupportedMessage : public ControlLayerException {
	public:
	UnsupportedMessage(unsigned wTransactionID=0)
		:ControlLayerException(wTransactionID)
	{}
};

/** Thrown when the control layer gets the wrong primitive */
class UnexpectedPrimitive : public ControlLayerException {
	public:
	UnexpectedPrimitive(unsigned wTransactionID=0)
		:ControlLayerException(wTransactionID)
	{}
};

/**  Thrown when a T3xx expires */
class Q931TimerExpired : public ControlLayerException {
	public:
	Q931TimerExpired(unsigned wTransactionID=0)
		:ControlLayerException(wTransactionID)
	{}
};

/** Thrown if we touch a removed transaction. */
class RemovedTransaction : public ControlLayerException {
	public:
	RemovedTransaction(unsigned wTransactionID=0)
		:ControlLayerException(wTransactionID)
	{}
};
//@}


}	//Control



/**@addtogroup Globals */
//@{
/** A single global transaction table in the global namespace. */
extern Control::TransactionTable gTransactionTable;
//@}



#endif

// vim: ts=4 sw=4

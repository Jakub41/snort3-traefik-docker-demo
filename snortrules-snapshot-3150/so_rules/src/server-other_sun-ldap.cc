//--------------------------------------------------------------------------
// Copyright (C) 2019-2021 Cisco and/or its affiliates. All rights reserved.
//
// This file may contain proprietary rules that were created, tested and
// certified by Sourcefire, Inc. (the "VRT Certified Rules") as well as
// rules that were created by Sourcefire and other third parties and
// distributed under the GNU General Public License (the "GPL Rules").
// The VRT Certified Rules contained in this file are the property of
// Sourcefire, Inc. Copyright 2005 Sourcefire, Inc. All Rights Reserved.
// The GPL Rules created by Sourcefire, Inc. are the property of
// Sourcefire, Inc. Copyright 2002-2005 Sourcefire, Inc. All Rights
// Reserved. All other GPL Rules are owned and copyrighted by their
// respective owners (please see www.snort.org/contributors for a list
// of owners and their respective copyrights). In order to determine what
// rules are VRT Certified Rules or GPL Rules, please refer to the VRT
// Certified Rules License Agreement.
//--------------------------------------------------------------------------
// server-other_sun-ldap.cc author Brandon Stultz <brastult@cisco.com>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "framework/cursor.h"
#include "protocols/packet.h"
#include "utils/util_ber.h"

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

using namespace snort;

static const char* rule_18101 = R"[Snort_SO_Rule](
alert tcp $EXTERNAL_NET any -> $HOME_NET [389,9833] (
	msg:"SERVER-OTHER Sun Directory Server LDAP denial of service attempt";
	soid:18101;
	flow:to_server,established;
	content:"|30|",depth 1;
	byte_jump:0,-1,relative;
	ber_data:0x30;
	ber_skip:0x02;
	so:eval;
	metadata:policy max-detect-ips drop;
	service:ldap;
	reference:cve,2006-0647;
	classtype:attempted-dos;
	gid:3; sid:18101; rev:4;
)
)[Snort_SO_Rule]";

static const unsigned rule_18101_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start();

   BerReader ber(c);

   BerElement e;

   if(!ber.read(cursor_normal, e))
      return IpsOption::NO_MATCH;

   // SearchRequest (0x63) or ModifyDNRequest (0x6C)
   if(e.type != 0x63 && e.type != 0x6C)
      return IpsOption::NO_MATCH;

   if(e.length > 1000)
      return IpsOption::MATCH;

   return IpsOption::NO_MATCH;
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_18101 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        4, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "18101", // name
        "SERVER-OTHER Sun Directory Server LDAP denial of service attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_18101,
    rule_18101_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_18101 = &so_18101.base;


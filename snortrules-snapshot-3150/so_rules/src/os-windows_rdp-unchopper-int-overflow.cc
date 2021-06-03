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
// os-windows_rdp-unchopper-int-overflow.cc author Brandon Stultz <brastult@cisco.com>

#include "main/snort_types.h"
#include "framework/so_rule.h"
#include "framework/cursor.h"
#include "protocols/packet.h"
#include "util_read.h"

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

using namespace snort;

static const char* rule_51369 = R"[Snort_SO_Rule](
alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (
	msg:"OS-WINDOWS Microsoft Windows RDP DecompressUnchopper integer overflow attempt";
	soid:51369;
	flow:to_server,established;
	content:"|03|",depth 1;
	content:"|02 F0|",distance 3, within 2;
	content:"|E1|",distance 19, within 1;
	so:eval;
	metadata:policy balanced-ips drop, policy connectivity-ips drop, policy max-detect-ips drop, policy security-ips drop;
	service:rdp;
	reference:cve,2019-1181;
	reference:cve,2019-1182;
	reference:url,portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-1181;
	reference:url,portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-1182;
	classtype:attempted-admin;
	gid:3; sid:51369; rev:2;
)
)[Snort_SO_Rule]";

static const unsigned rule_51369_len = 0;

static IpsOption::EvalStatus eval(void*, Cursor& c, Packet* p)
{
   const uint8_t *cursor_normal = c.start(),
                 *end_of_buffer = c.endo();

   uint16_t num_frames;
   uint32_t uncompressed_len, frame_len,
            check, total = 0;

   // check if we can read:
   //  num_frames       (2 bytes)
   //  uncompressed_len (4 bytes)
   if(cursor_normal + 6 > end_of_buffer)
      return IpsOption::NO_MATCH;

   num_frames = read_little_16_inc(cursor_normal);
   uncompressed_len = read_little_32_inc(cursor_normal);

   // check for CVE-2019-1182
   if(uncompressed_len >= 0xFFFFE000)
      return IpsOption::MATCH;

   // limit num_frames
   if(num_frames > 25)
      num_frames = 25;

   for(unsigned i = 0; i < num_frames; i++)
   {
      // check if we can read:
      //  frame_len (4 bytes)
      if(cursor_normal + 4 > end_of_buffer)
         return IpsOption::NO_MATCH;

      frame_len = read_little_32(cursor_normal);

      // check for CVE-2019-1181
      check = frame_len + 4;

      if(check < frame_len)
         return IpsOption::MATCH;

      frame_len = check;

      // check for CVE-2019-1181
      check = total + frame_len;

      if(check < total)
         return IpsOption::MATCH;

      total = check;

      // check if we can jump to the next frame
      if(frame_len > end_of_buffer - cursor_normal)
         return IpsOption::NO_MATCH;

      // jump to next frame
      cursor_normal += frame_len;
   }

   return IpsOption::NO_MATCH; 
}

static SoEvalFunc ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return eval;
}

static const SoApi so_51369 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        2, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "51369", // name
        "OS-WINDOWS Microsoft Windows RDP DecompressUnchopper integer overflow attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_51369,
    rule_51369_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,    // ctor
    nullptr  // dtor
};

const BaseApi* pso_51369 = &so_51369.base;


/*
 * Copyright 2007-2018 Adrian Thurston <thurston@colm.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdbool.h>

#include <assert.h>

#include "redfsm.h"
#include "compiler.h"

void execAction( struct pda_run *pdaRun, GenAction *genAction )
{
	for ( InlineList::Iter item = *genAction->inlineList; item.lte(); item++ ) {
		switch ( item->type ) {
		case InlineItem::Text:
			assert(false);
			break;
		case InlineItem::LmSetActId:
			pdaRun->act = item->longestMatchPart->longestMatchId;
			break;
		case InlineItem::LmSetTokEnd:
			pdaRun->tokend = pdaRun->tokpref + ( pdaRun->p - pdaRun->start ) + 1;
			break;
		case InlineItem::LmInitTokStart:
			assert(false);
			break;
		case InlineItem::LmInitAct:
			pdaRun->act = 0;
			break;
		case InlineItem::LmSetTokStart:
			pdaRun->tokstart = pdaRun->p;
			break;
		case InlineItem::LmSwitch:
			/* If the switch handles error then we also forced the error state. It
			 * will exist. */
			if ( item->tokenRegion->lmSwitchHandlesError && pdaRun->act == 0 ) {
				pdaRun->fsm_cs = pdaRun->fsm_tables->error_state;
			}
			else {
				for ( TokenInstanceListReg::Iter lmi = item->tokenRegion->tokenInstanceList; 
						lmi.lte(); lmi++ )
				{
					if ( lmi->inLmSelect && pdaRun->act == lmi->longestMatchId )
						pdaRun->matched_token = lmi->tokenDef->tdLangEl->id;
				}
			}
			pdaRun->return_result = true;
			pdaRun->skip_tokpref = true;
			break;
		case InlineItem::LmOnLast:
			pdaRun->p += 1;
			pdaRun->tokend = pdaRun->tokpref + ( pdaRun->p - pdaRun->start );
			pdaRun->matched_token = item->longestMatchPart->tokenDef->tdLangEl->id;
			pdaRun->return_result = true;
			break;
		case InlineItem::LmOnNext:
			pdaRun->tokend = pdaRun->tokpref + ( pdaRun->p - pdaRun->start );
			pdaRun->matched_token = item->longestMatchPart->tokenDef->tdLangEl->id;
			pdaRun->return_result = true;
			break;
		case InlineItem::LmOnLagBehind:
			pdaRun->matched_token = item->longestMatchPart->tokenDef->tdLangEl->id;
			pdaRun->return_result = true;
			pdaRun->skip_tokpref = true;
			break;
		}
	}

	if ( genAction->markType == MarkMark )
		pdaRun->mark[genAction->markId-1] = pdaRun->p;
}

extern "C" void internalFsmExecute( struct pda_run *pdaRun, struct input_impl *inputStream )
{
	int _klen;
	unsigned int _trans;
	const long *_acts;
	unsigned int _nacts;
	const char *_keys;
		
	pdaRun->start = pdaRun->p;

	/* Init the token match to nothing (the sentinal). */
	pdaRun->matched_token = 0;

/*_resume:*/
	if ( pdaRun->fsm_cs == pdaRun->fsm_tables->error_state )
		goto out;

	if ( pdaRun->p == pdaRun->pe )
		goto out;

_loop_head:
	_acts = pdaRun->fsm_tables->actions + pdaRun->fsm_tables->from_state_actions[pdaRun->fsm_cs];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 )
		execAction( pdaRun, pdaRun->fsm_tables->action_switch[*_acts++] );

	_keys = pdaRun->fsm_tables->trans_keys + pdaRun->fsm_tables->key_offsets[pdaRun->fsm_cs];
	_trans = pdaRun->fsm_tables->index_offsets[pdaRun->fsm_cs];

	_klen = pdaRun->fsm_tables->single_lengths[pdaRun->fsm_cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + _klen - 1;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + ((_upper-_lower) >> 1);
			if ( (*pdaRun->p) < *_mid )
				_upper = _mid - 1;
			else if ( (*pdaRun->p) > *_mid )
				_lower = _mid + 1;
			else {
				_trans += (_mid - _keys);
				goto _match;
			}
		}
		_keys += _klen;
		_trans += _klen;
	}

	_klen = pdaRun->fsm_tables->range_lengths[pdaRun->fsm_cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + (_klen<<1) - 2;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + (((_upper-_lower) >> 1) & ~1);
			if ( (*pdaRun->p) < _mid[0] )
				_upper = _mid - 2;
			else if ( (*pdaRun->p) > _mid[1] )
				_lower = _mid + 2;
			else {
				_trans += ((_mid - _keys)>>1);
				goto _match;
			}
		}
		_trans += _klen;
	}

_match:
	pdaRun->fsm_cs = pdaRun->fsm_tables->transTargsWI[_trans];

	if ( pdaRun->fsm_tables->transActionsWI[_trans] == 0 )
		goto _again;

	pdaRun->return_result = false;
	pdaRun->skip_tokpref = false;
	_acts = pdaRun->fsm_tables->actions + pdaRun->fsm_tables->transActionsWI[_trans];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 )
		execAction( pdaRun, pdaRun->fsm_tables->action_switch[*_acts++] );
	if ( pdaRun->return_result ) {
		if ( pdaRun->skip_tokpref )
			goto skip_tokpref;
		goto final;
	}

_again:
	_acts = pdaRun->fsm_tables->actions + pdaRun->fsm_tables->to_state_actions[pdaRun->fsm_cs];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 )
		execAction( pdaRun, pdaRun->fsm_tables->action_switch[*_acts++] );

	if ( pdaRun->fsm_cs == pdaRun->fsm_tables->error_state )
		goto out;

	if ( ++pdaRun->p != pdaRun->pe )
		goto _loop_head;
out:
	if ( pdaRun->scan_eof ) {
		pdaRun->return_result = false;
		pdaRun->skip_tokpref = false;
		_acts = pdaRun->fsm_tables->actions + pdaRun->fsm_tables->eof_actions[pdaRun->fsm_cs];
		_nacts = (unsigned int) *_acts++;

		if ( pdaRun->fsm_tables->eof_targs[pdaRun->fsm_cs] >= 0 )
			pdaRun->fsm_cs = pdaRun->fsm_tables->eof_targs[pdaRun->fsm_cs];

		while ( _nacts-- > 0 )
			execAction( pdaRun, pdaRun->fsm_tables->action_switch[*_acts++] );
		if ( pdaRun->return_result ) {
			if ( pdaRun->skip_tokpref )
				goto skip_tokpref;
			goto final;
		}
	}

final:

	if ( pdaRun->p != 0 )
		pdaRun->tokpref += pdaRun->p - pdaRun->start;
skip_tokpref:
	{}
}

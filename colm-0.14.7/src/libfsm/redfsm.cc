/*
 * Copyright 2001-2018 Adrian Thurston <thurston@colm.net>
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

#include "redfsm.h"
#include "avlmap.h"
#include "mergesort.h"
#include "fsmgraph.h"
#include <iostream>
#include <sstream>
#include <ctime>

using std::ostringstream;

GenInlineItem::~GenInlineItem()
{
	if ( children != 0 ) {
		children->empty();
		delete children;
	}
}

string GenAction::nameOrLoc()
{
	if ( name.empty() ) {
		ostringstream ret;
		ret << loc.line << ":" << loc.col;
		return ret.str();
	}
	else {
		return name;
	}
}

RedFsmAp::RedFsmAp( FsmCtx *fsmCtx, int machineId )
:
	keyOps(fsmCtx->keyOps),
	fsmCtx(fsmCtx),
	machineId(machineId),
	forcedErrorState(false),
	nextActionId(0),
	nextTransId(0),
	nextCondId(0),
	startState(0),
	errState(0),
	errTrans(0),
	errCond(0),
	firstFinState(0),
	numFinStates(0),
	bAnyToStateActions(false),
	bAnyFromStateActions(false),
	bAnyRegActions(false),
	bAnyEofActions(false),
	bAnyEofTrans(false),
	bAnyEofActivity(false),
	bAnyActionGotos(false),
	bAnyActionCalls(false),
	bAnyActionNcalls(false),
	bAnyActionRets(false),
	bAnyActionNrets(false),
	bAnyActionByValControl(false),
	bAnyRegActionRets(false),
	bAnyRegActionByValControl(false),
	bAnyRegNextStmt(false),
	bAnyRegCurStateRef(false),
	bAnyRegBreak(false),
	bAnyRegNbreak(false),
	bUsingAct(false),
	bAnyNfaStates(false),
	bAnyNfaPushPops(false),
	bAnyNfaPushes(false),
	bAnyNfaPops(false),
	bAnyTransCondRefs(false),
	bAnyNfaCondRefs(false),
	nextClass(0),
	classMap(0)
{
}

RedFsmAp::~RedFsmAp()
{
	for ( RedStateList::Iter st = stateList; st.lte(); st++ ) {
		delete[] st->transList;
		if ( st->nfaTargs != 0 )
			delete st->nfaTargs;
		if ( st->inConds != 0 )
			delete[] st->inConds;
		if ( st->inCondTests != 0 )
			delete[] st->inCondTests;
	}

	delete[] allStates;
	if ( classMap != 0 )
		delete[] classMap;

	for ( TransApSet::Iter ti = transSet; ti.lte(); ti++ ) {
		if ( ti->condSpace != 0 )
			delete[] ti->v.outConds;
	}

	condSet.empty();
	transSet.empty();
}

/* Does the machine have any actions. */
bool RedFsmAp::anyActions()
{
	return actionMap.length() > 0;
}

void RedFsmAp::depthFirstOrdering( RedStateAp *state )
{
	/* Nothing to do if the state is already on the list. */
	if ( state->onStateList )
		return;

	/* Doing depth first, put state on the list. */
	state->onStateList = true;
	stateList.append( state );
	
	/* At this point transitions should only be in ranges. */
	assert( state->outSingle.length() == 0 );
	assert( state->defTrans == 0 );

	/* Recurse on everything ranges. */
	for ( RedTransList::Iter rtel = state->outRange; rtel.lte(); rtel++ ) {
		for ( int c = 0; c < rtel->value->numConds(); c++ ) {
			RedCondPair *cond = rtel->value->outCond( c );
			if ( cond->targ != 0 )
				depthFirstOrdering( cond->targ );
		}
	}

	if ( state->nfaTargs ) {
		for ( RedNfaTargs::Iter s = *state->nfaTargs; s.lte(); s++ )
			depthFirstOrdering( s->state );
	}
}

/* Ordering states by transition connections. */
void RedFsmAp::depthFirstOrdering()
{
	/* Init on state list flags. */
	for ( RedStateList::Iter st = stateList; st.lte(); st++ )
		st->onStateList = false;
	
	/* Clear out the state list, we will rebuild it. */
	int stateListLen = stateList.length();
	stateList.abandon();

	/* Add back to the state list from the start state and all other entry
	 * points. */
	if ( startState != 0 )
		depthFirstOrdering( startState );
	for ( RedStateSet::Iter en = entryPoints; en.lte(); en++ )
		depthFirstOrdering( *en );
	if ( forcedErrorState )
		depthFirstOrdering( errState );
	
	/* Make sure we put everything back on. */
	assert( stateListLen == stateList.length() );
}

void RedFsmAp::breadthFirstAdd( RedStateAp *state )
{
	if ( state->onStateList )
		return;

	state->onStateList = true;
	stateList.append( state );
}

void RedFsmAp::breadthFirstOrdering()
{
	/* Init on state list flags. */
	for ( RedStateList::Iter st = stateList; st.lte(); st++ )
		st->onStateList = false;
	
	/* Clear out the state list, we will rebuild it. */
	int stateListLen = stateList.length();
	stateList.abandon();

	if ( startState != 0 )
		breadthFirstAdd( startState );
	
	int depth = 0;
	int nextLevel = stateList.length();
	int pos = 0;

	/* To implement breadth-first we traverse the current list (assuming a
	 * start state) and add children. */
	RedStateAp *cur = stateList.head;
	while ( cur != 0 ) {
		/* Recurse on everything ranges. */
		for ( RedTransList::Iter rtel = cur->outRange; rtel.lte(); rtel++ ) {
			for ( int c = 0; c < rtel->value->numConds(); c++ ) {
				RedCondPair *cond = rtel->value->outCond( c );
				if ( cond->targ != 0 )
					breadthFirstAdd( cond->targ );
			}
		}

		if ( cur->nfaTargs ) {
			for ( RedNfaTargs::Iter s = *cur->nfaTargs; s.lte(); s++ )
				breadthFirstAdd( s->state );
		}

		cur = cur->next;
		pos += 1;

		if ( pos == nextLevel ) {
			depth += 1;
			nextLevel = stateList.length();
		}
	}

	for ( RedStateSet::Iter en = entryPoints; en.lte(); en++ )
		depthFirstOrdering( *en );
	if ( forcedErrorState )
		depthFirstOrdering( errState );

	assert( stateListLen == stateList.length() );
}

#ifdef SCORE_ORDERING
void RedFsmAp::readScores()
{
	/*
	 * Reads processed transitions logged by ASM codegen when LOG_TRANS is
	 * enabled. Process with:
	 *
	 * cat trans-log | sort -n -k 1 -k 2 -k 3 | uniq -c | sort -r -n -k1 -r > scores
	 */
	FILE *sfn = fopen( "scores", "r" );

	scores = new long*[nextStateId];
	for ( int i = 0; i < nextStateId; i++ ) {
		scores[i] = new long[256];
		memset( scores[i], 0, sizeof(long) * 256 );
	}

	long score, m, state, ch;
	while ( true ) {
		int n = fscanf( sfn, "%ld %ld %ld %ld\n", &score, &m, &state, &ch );
		if ( n != 4 )
			break;
		if ( m == machineId )
			scores[state][ch] = score;
	}
	fclose( sfn );

	/* Init on state list flags. */
	for ( RedStateList::Iter st = stateList; st.lte(); st++ ) {
		RedTransList::Iter rtel = st->outRange;
		int chi = 0;
		while ( rtel.lte() ) {
			/* 1. Bring chi up to lower end of out range. */
			while ( chi < rtel->lowKey.getVal() ) {
				chi++;
			}

			/* 2. While inside lower, add in score. */
			while ( chi <= rtel->highKey.getVal() ) {
				rtel->score += scores[st->id][chi];
				chi++;
			}

			/* 3. Next range. */
			rtel++;
		}
	}
}

/* This second pass will collect any states that didn't make it in the first
 * pass. Used for depth-first and breadth-first passes. */
void RedFsmAp::scoreSecondPass( RedStateAp *state )
{
	/* Nothing to do if the state is already on the list. */
	if ( state->onListRest )
		return;

	/* Doing depth first, put state on the list. */
	state->onListRest = true;

	if ( !state->onStateList ) {
		state->onStateList = true;
		stateList.append( state );
	}
	
	/* At this point transitions should only be in ranges. */
	assert( state->outSingle.length() == 0 );
	assert( state->defTrans == 0 );

	/* Recurse on everything ranges. */
	for ( RedTransList::Iter rtel = state->outRange; rtel.lte(); rtel++ ) {
		for ( int c = 0; c < rtel->value->numConds(); c++ ) {
			RedCondPair *cond = rtel->value->outCond( c );
			if ( cond->targ != 0 )
				scoreSecondPass( cond->targ );
		}
	}

	if ( state->nfaTargs ) {
		for ( RedNfaTargs::Iter s = *state->nfaTargs; s.lte(); s++ )
			scoreSecondPass( s->state );
	}
}

void RedFsmAp::scoreOrderingDepth( RedStateAp *state )
{
	/* Nothing to do if the state is already on the list. */
	if ( state->onStateList )
		return;

	/* Doing depth first, put state on the list. */
	state->onStateList = true;
	stateList.append( state );

	/* At this point transitions should only be in ranges. */
	assert( state->outSingle.length() == 0 );
	assert( state->defTrans == 0 );

	/* Recurse on everything ranges. */
	for ( RedTransList::Iter rtel = state->outRange; rtel.lte(); rtel++ ) {
		if ( rtel->score > 10 ) {
			for ( int c = 0; c < rtel->value->numConds(); c++ ) {
				RedCondPair *cond = rtel->value->outCond( c );
				if ( cond->targ != 0 )
					scoreOrderingDepth( cond->targ );
			}
		}
	}
}

void RedFsmAp::scoreOrderingDepth()
{
	readScores();

	/* Init on state list flags. */
	for ( RedStateList::Iter st = stateList; st.lte(); st++ ) {
		st->onStateList = false;
		st->onListRest = false;
	}
	
	/* Clear out the state list, we will rebuild it. */
	int stateListLen = stateList.length();
	stateList.abandon();

	scoreOrderingDepth( startState );

	scoreSecondPass( startState );
	for ( RedStateSet::Iter en = entryPoints; en.lte(); en++ )
		scoreSecondPass( *en );
	if ( forcedErrorState )
		scoreSecondPass( errState );

	assert( stateListLen == stateList.length() );
}

void RedFsmAp::scoreOrderingBreadth()
{
	readScores();

	/* Init on state list flags. */
	for ( RedStateList::Iter st = stateList; st.lte(); st++ ) {
		st->onStateList = false;
		st->onListRest = false;
	}
	
	/* Clear out the state list, we will rebuild it. */
	int stateListLen = stateList.length();
	stateList.abandon();

	if ( startState != 0 )
		breadthFirstAdd( startState );
	
	int depth = 0;
	int nextLevel = stateList.length();
	int pos = 0;

	/* To implement breadth-first we traverse the current list (assuming a
	 * start state) and add children. */
	RedStateAp *cur = stateList.head;
	while ( cur != 0 ) {
		/* Recurse on everything ranges. */
		for ( RedTransList::Iter rtel = cur->outRange; rtel.lte(); rtel++ ) {
			if ( rtel->score > 100 ) {
				for ( int c = 0; c < rtel->value->numConds(); c++ ) {
					RedCondPair *cond = rtel->value->outCond( c );
					if ( cond->targ != 0 )
						breadthFirstAdd( cond->targ );
				}
			}
		}

		cur = cur->next;
		pos += 1;

		if ( pos == nextLevel ) {
			depth += 1;
			nextLevel = stateList.length();
		}
	}

	scoreSecondPass( startState );
	for ( RedStateSet::Iter en = entryPoints; en.lte(); en++ )
		scoreSecondPass( *en );
	if ( forcedErrorState )
		scoreSecondPass( errState );

	assert( stateListLen == stateList.length() );
}
#endif

void RedFsmAp::randomizedOrdering()
{
	for ( RedStateList::Iter st = stateList; st.lte(); st++ )
		st->onStateList = false;

	/* Clear out the state list, we will rebuild it. */
	int stateListLen = stateList.length();
	stateList.abandon();

	srand( time( 0 ) );

	for ( int i = nextStateId; i > 0; i-- ) {
		/* Pick one from 0 ... i (how many are left). */
		int nth = rand() % i;

		/* Go forward through the list adding the nth. Need to scan because
		 * there are items already added in the list. */
		for ( int j = 0; j < nextStateId; j++ ) {
			if ( !allStates[j].onStateList ) {
				if ( nth == 0 ) {
					/* Add. */
					allStates[j].onStateList = true;
					stateList.append( &allStates[j] );
					break;
				}
				else {
					nth -= 1;
				}
			}
		}
	}
	assert( stateListLen == stateList.length() );
}

/* Assign state ids by appearance in the state list. */
void RedFsmAp::sequentialStateIds()
{
	/* Table based machines depend on the state numbers starting at zero. */
	nextStateId = 0;
	for ( RedStateList::Iter st = stateList; st.lte(); st++ )
		st->id = nextStateId++;
}

/* Stable sort the states by final state status. */
void RedFsmAp::sortStatesByFinal()
{
	/* Move forward through the list and move final states onto the end. */
	RedStateAp *state = 0;
	RedStateAp *next = stateList.head;
	RedStateAp *last = stateList.tail;
	while ( state != last ) {
		/* Move forward and load up the next. */
		state = next;
		next = state->next;

		/* Throw to the end? */
		if ( state->isFinal ) {
			stateList.detach( state );
			stateList.append( state );
		}
	}
}

/* Assign state ids by final state state status. */
void RedFsmAp::sortStateIdsByFinal()
{
	/* Table based machines depend on this starting at zero. */
	nextStateId = 0;

	/* First pass to assign non final ids. */
	for ( RedStateList::Iter st = stateList; st.lte(); st++ ) {
		if ( ! st->isFinal ) 
			st->id = nextStateId++;
	}

	/* Second pass to assign final ids. */
	for ( RedStateList::Iter st = stateList; st.lte(); st++ ) {
		if ( st->isFinal ) 
			st->id = nextStateId++;
	}
}

struct CmpStateById
{
	static int compare( RedStateAp *st1, RedStateAp *st2 )
	{
		if ( st1->id < st2->id )
			return -1;
		else if ( st1->id > st2->id )
			return 1;
		else
			return 0;
	}
};

void RedFsmAp::sortByStateId()
{
	/* Make the array. */
	int pos = 0;
	RedStateAp **ptrList = new RedStateAp*[stateList.length()];
	for ( RedStateList::Iter st = stateList; st.lte(); st++, pos++ )
		ptrList[pos] = st;
	
	MergeSort<RedStateAp*, CmpStateById> mergeSort;
	mergeSort.sort( ptrList, stateList.length() );

	stateList.abandon();
	for ( int st = 0; st < pos; st++ )
		stateList.append( ptrList[st] );

	delete[] ptrList;
}

/* Find the final state with the lowest id. */
void RedFsmAp::findFirstFinState()
{
	for ( RedStateList::Iter st = stateList; st.lte(); st++ ) {
		if ( st->isFinal && (firstFinState == 0 || st->id < firstFinState->id) )
			firstFinState = st;
	}
}

void RedFsmAp::assignActionLocs()
{
	int nextLocation = 0;
	for ( GenActionTableMap::Iter act = actionMap; act.lte(); act++ ) {
		/* Store the loc, skip over the array and a null terminator. */
		act->location = nextLocation;
		nextLocation += act->key.length() + 1;		
	}
}

/* Check if we can extend the current range by displacing any ranges
 * ahead to the singles. */
bool RedFsmAp::canExtend( const RedTransList &list, int pos )
{
	/* Get the transition that we want to extend. */
	RedTransAp *extendTrans = list[pos].value;

	/* Look ahead in the transition list. */
	for ( int next = pos + 1; next < list.length(); pos++, next++ ) {
		/* If they are not continuous then cannot extend. */
		Key nextKey = list[next].lowKey;
		keyOps->decrement( nextKey );
		if ( keyOps->ne( list[pos].highKey, nextKey ) )
			break;

		/* Check for the extenstion property. */
		if ( extendTrans == list[next].value )
			return true;

		/* If the span of the next element is more than one, then don't keep
		 * checking, it won't be moved to single. */
		unsigned long long nextSpan = keyOps->span( list[next].lowKey, list[next].highKey );
		if ( nextSpan > 1 )
			break;
	}
	return false;
}

/* Move ranges to the singles list if it means we can extend some ranges, or if
 * the spans are of length one. */
void RedFsmAp::moveSelectTransToSingle( RedStateAp *state )
{
	RedTransList &range = state->outRange;
	RedTransList &single = state->outSingle;
	for ( int rpos = 0; rpos < range.length(); ) {
		/* Check if this is a range we can extend. */
		if ( canExtend( range, rpos ) ) {
			/* Transfer singles over. */
			while ( range[rpos].value != range[rpos+1].value ) {
				/* Transfer the range to single. */
				single.append( range[rpos+1] );
				range.remove( rpos+1 );
			}

			/* Extend. */
			range[rpos].highKey = range[rpos+1].highKey;
			range.remove( rpos+1 );
		}
		/* Maybe move it to the singles. */
		else if ( keyOps->span( range[rpos].lowKey, range[rpos].highKey ) == 1 ) {
			single.append( range[rpos] );
			range.remove( rpos );
		}
		else {
			/* Keeping it in the ranges. */
			rpos += 1;
		}
	}
}

void RedFsmAp::moveAllTransToSingle( RedStateAp *state )
{
	RedTransList &range = state->outRange;
	RedTransList &single = state->outSingle;
	for ( int rpos = 0; rpos < range.length(); rpos++ ) {

		RedTransEl el = range[rpos];
		unsigned long long span = keyOps->span( el.lowKey, el.highKey );

		Key key = el.lowKey;
		for ( unsigned long long pos = 0; pos < span; pos++ ) {
			el.lowKey = el.highKey = key;
			single.append( el );
			keyOps->increment( key );
		}
	}
	range.empty();
}

/* Look through ranges and choose suitable single character transitions. */
void RedFsmAp::moveSelectTransToSingle()
{
	/* Loop the states. */
	for ( RedStateList::Iter st = stateList; st.lte(); st++ ) {
		/* Rewrite the transition list taking out the suitable single
		 * transtions. */
		moveSelectTransToSingle( st );
	}
}

void RedFsmAp::moveAllTransToSingle()
{
	/* Loop the states. */
	for ( RedStateList::Iter st = stateList; st.lte(); st++ ) {
		/* Rewrite the transition list taking out the suitable single
		 * transtions. */
		moveAllTransToSingle( st );
	}
}

void RedFsmAp::makeFlat()
{
	for ( RedStateList::Iter st = stateList; st.lte(); st++ ) {
		if ( st->outRange.length() == 0 ) {
			st->lowKey = st->highKey = 0;
			st->transList = 0;
		}
		else {
			st->lowKey = st->outRange[0].lowKey;
			st->highKey = st->outRange[st->outRange.length()-1].highKey;
			unsigned long long span = keyOps->span( st->lowKey, st->highKey );
			st->transList = new RedTransAp*[ span ];
			memset( st->transList, 0, sizeof(RedTransAp*)*span );
			
			for ( RedTransList::Iter trans = st->outRange; trans.lte(); trans++ ) {
				unsigned long long base, trSpan;
				base = keyOps->span( st->lowKey, trans->lowKey )-1;
				trSpan = keyOps->span( trans->lowKey, trans->highKey );
				for ( unsigned long long pos = 0; pos < trSpan; pos++ )
					st->transList[base+pos] = trans->value;
			}

			/* Fill in the gaps with the default transition. */
			for ( unsigned long long pos = 0; pos < span; pos++ ) {
				if ( st->transList[pos] == 0 )
					st->transList[pos] = st->defTrans;
			}
		}
	}
}

void RedFsmAp::characterClass( EquivList &equiv )
{
	/* Find the global low and high keys. */
	bool anyTrans = false;
	Key lowKey = keyOps->maxKey;
	Key highKey = keyOps->minKey;
	for ( RedStateList::Iter st = stateList; st.lte(); st++ ) {
		if ( st->outRange.length() == 0 )
			continue;

		st->lowKey = st->outRange[0].lowKey;
		st->highKey = st->outRange[st->outRange.length()-1].highKey;

		if ( keyOps->lt( st->lowKey, lowKey ) )
			lowKey = st->lowKey;

		if ( keyOps->gt( st->highKey, highKey ) )
			highKey = st->highKey;

		anyTrans = true;
	}

	if ( ! anyTrans ) {
		this->lowKey = lowKey;
		this->highKey = highKey;
		this->classMap = 0;
		this->nextClass = 1;
		return;
	}

	long long next = 1;
	equiv.append( new EquivClass( lowKey, highKey, next++ ) );

	/* Start with a single equivalence class and break it up using range
	 * boundaries of each state. This will tell us what the equivalence class
	 * ranges are. These are the ranges that always go to the same state,
	 * across all states. */
	for ( RedStateList::Iter st = stateList; st.lte(); st++ ) {
		if ( st->outRange.length() == 0 )
			continue;

		EquivList newList;
		PairKeyMap uniqPairs;

		/* What is the set of unique transitions (*for this state) */
		EquivAlloc uniqTrans;
		for ( RedTransList::Iter rtel = st->outRange; rtel.lte(); rtel++ ) {
			if ( ! uniqTrans.find( rtel->value ) )
				uniqTrans.insert( rtel->value, next++ );
		}

		/* Merge with whole-machine equiv classes. */
                typedef RangePairIter< PiList<EquivClass>, PiVector<RedTransEl> > RangePairIterPiListEquivClassPiVectorRedTransEl;
		for ( RangePairIterPiListEquivClassPiVectorRedTransEl
				pair( fsmCtx, equiv, st->outRange ); !pair.end(); pair++ )
		{
			switch ( pair.userState ) {

			case RangePairIterPiListEquivClassPiVectorRedTransEl::RangeOverlap: {
				/* Look up the char for s2. */
				EquivAllocEl *s2El = uniqTrans.find( pair.s2Tel.trans->value );

				/* Can't use either equiv classes, find uniques. */
				PairKey pairKey( pair.s1Tel.trans->value, s2El->value );
				PairKeyMapEl *pairEl = uniqPairs.find( pairKey );
				if ( ! pairEl ) 
					pairEl = uniqPairs.insert( pairKey, next++ );

				EquivClass *equivClass = new EquivClass(
						pair.s1Tel.lowKey, pair.s1Tel.highKey,
						pairEl->value );
				newList.append( equivClass );
				break;
			}

			case RangePairIterPiListEquivClassPiVectorRedTransEl::RangeInS1: {
				EquivClass *equivClass = new EquivClass(
						pair.s1Tel.lowKey, pair.s1Tel.highKey,
						pair.s1Tel.trans->value );
				newList.append( equivClass );
				break;
			}

			case RangePairIterPiListEquivClassPiVectorRedTransEl::RangeInS2: {
				/* Look up the char for s2. */
				EquivAllocEl *s2El = uniqTrans.find( pair.s2Tel.trans->value );

				EquivClass *equivClass = new EquivClass(
						pair.s2Tel.lowKey, pair.s2Tel.highKey,
						s2El->value );
				newList.append( equivClass );
				break;
			}

			case RangePairIterPiListEquivClassPiVectorRedTransEl::BreakS1:
			case RangePairIterPiListEquivClassPiVectorRedTransEl::BreakS2:
				break;
			}
		}

		equiv.empty();
		equiv.transfer( newList );
	}
	
	/* Reduce to sequential. */
	next = 0;
	BstMap<long long, long long> map;
	for ( EquivClass *c = equiv.head; c != 0; c = c->next ) {
		BstMapEl<long long, long long> *el = map.find( c->value );
		if ( ! el ) 
			el = map.insert( c->value, next++ );
		c->value = el->value;
	}

	/* Build the map and emit arrays from the range-based equiv classes. Will
	 * likely crash if there are no transitions in the FSM. */
	long long maxSpan = keyOps->span( lowKey, highKey );
	long long *dest = new long long[maxSpan];
	memset( dest, 0, sizeof(long long) * maxSpan );

	for ( EquivClass *c = equiv.head; c != 0; c = c->next ) {
		long long base = keyOps->span( lowKey, c->lowKey ) - 1;
		long long span = keyOps->span( c->lowKey, c->highKey );
		for ( long long s = 0; s < span; s++ )
			dest[base + s] = c->value;
	}

	this->lowKey = lowKey;
	this->highKey = highKey;
	this->classMap = dest;
	this->nextClass = next;

}

void RedFsmAp::makeFlatClass()
{
	EquivList equiv;
	characterClass( equiv );

	/* Expand the transitions. This uses the equivalence classes. */
	for ( RedStateList::Iter st = stateList; st.lte(); st++ ) {
		if ( st->outRange.length() == 0 ) {
			st->lowKey = st->highKey = 0;
			st->low = st->high = 0;
			st->transList = 0;
		}
		else {
			st->lowKey = st->outRange[0].lowKey;
			st->highKey = st->outRange[st->outRange.length()-1].highKey;

			/* Compute low and high in class space. Use a pair iter to find all
			 * the clases. Alleviates the need to iterate the whole input
			 * alphabet. */
			st->low = nextClass;
			st->high = -1;
			for ( RangePairIter< PiList<EquivClass>, PiVector<RedTransEl> >
					pair( fsmCtx, equiv, st->outRange ); !pair.end(); pair++ )
			{
				if ( pair.userState == RangePairIter<PiList<EquivClass>, PiVector<RedTransEl> >::RangeOverlap ||
						pair.userState == RangePairIter<PiList<EquivClass>, PiVector<RedTransEl> >::RangeInS2 )
				{
					long long off = keyOps->span( lowKey, pair.s2Tel.lowKey ) - 1;
					if ( classMap[off] < st->low )
						st->low = classMap[off];
					if ( classMap[off] > st->high )
						st->high = classMap[off];
				}
			}

			long long span = st->high - st->low + 1;
			st->transList = new RedTransAp*[ span ];
			memset( st->transList, 0, sizeof(RedTransAp*)*span );
			
			for ( RangePairIter< PiList<EquivClass>, PiVector<RedTransEl> >
					pair( fsmCtx, equiv, st->outRange ); !pair.end(); pair++ )
			{
				if ( pair.userState == RangePairIter< PiList<EquivClass>, PiVector<RedTransEl> >::RangeOverlap ||
						pair.userState == RangePairIter< PiList<EquivClass>, PiVector<RedTransEl> >::RangeInS2 )
				{
					long long off = keyOps->span( lowKey, pair.s2Tel.lowKey ) - 1;
					st->transList[ classMap[off] - st->low ] = pair.s2Tel.trans->value;
				}
			}

			/* Fill in the gaps with the default transition. */
			for ( long long pos = 0; pos < span; pos++ ) {
				if ( st->transList[pos] == 0 )
					st->transList[pos] = st->defTrans;
			}
		}
	}

	equiv.empty();
}


/* A default transition has been picked, move it from the outRange to the
 * default pointer. */
void RedFsmAp::moveToDefault( RedTransAp *defTrans, RedStateAp *state )
{
	/* Rewrite the outRange, omitting any ranges that use 
	 * the picked default. */
	RedTransList outRange;
	for ( RedTransList::Iter rtel = state->outRange; rtel.lte(); rtel++ ) {
		/* If it does not take the default, copy it over. */
		if ( rtel->value != defTrans )
			outRange.append( *rtel );
	}

	/* Save off the range we just created into the state's range. */
	state->outRange.transfer( outRange );

	/* Store the default. */
	state->defTrans = defTrans;
}

bool RedFsmAp::alphabetCovered( RedTransList &outRange )
{
	/* Cannot cover without any out ranges. */
	if ( outRange.length() == 0 )
		return false;

	/* If the first range doesn't start at the the lower bound then the
	 * alphabet is not covered. */
	RedTransList::Iter rtel = outRange;
	if ( keyOps->lt( keyOps->minKey, rtel->lowKey ) )
		return false;

	/* Check that every range is next to the previous one. */
	rtel.increment();
	for ( ; rtel.lte(); rtel++ ) {
		Key highKey = rtel[-1].highKey;
		keyOps->increment( highKey );
		if ( keyOps->ne( highKey, rtel->lowKey ) )
			return false;
	}

	/* The last must extend to the upper bound. */
	RedTransEl *last = &outRange[outRange.length()-1];
	if ( keyOps->lt( last->highKey, keyOps->maxKey ) )
		return false;

	return true;
}

RedTransAp *RedFsmAp::chooseDefaultSpan( RedStateAp *state )
{
	/* Make a set of transitions from the outRange. */
	RedTransSet stateTransSet;
	for ( RedTransList::Iter rtel = state->outRange; rtel.lte(); rtel++ )
		stateTransSet.insert( rtel->value );
	
	/* For each transition in the find how many alphabet characters the
	 * transition spans. */
	unsigned long long *span = new unsigned long long[stateTransSet.length()];
	memset( span, 0, sizeof(unsigned long long) * stateTransSet.length() );
	for ( RedTransList::Iter rtel = state->outRange; rtel.lte(); rtel++ ) {
		/* Lookup the transition in the set. */
		RedTransAp **inSet = stateTransSet.find( rtel->value );
		int pos = inSet - stateTransSet.data;
		span[pos] += keyOps->span( rtel->lowKey, rtel->highKey );
	}

	/* Find the max span, choose it for making the default. */
	RedTransAp *maxTrans = 0;
	unsigned long long maxSpan = 0;
	for ( RedTransSet::Iter rtel = stateTransSet; rtel.lte(); rtel++ ) {
		if ( span[rtel.pos()] > maxSpan ) {
			maxSpan = span[rtel.pos()];
			maxTrans = *rtel;
		}
	}

	delete[] span;
	return maxTrans;
}

/* Pick default transitions from ranges for the states. */
void RedFsmAp::chooseDefaultSpan()
{
	/* Loop the states. */
	for ( RedStateList::Iter st = stateList; st.lte(); st++ ) {
		/* Only pick a default transition if the alphabet is covered. This
		 * avoids any transitions in the out range that go to error and avoids
		 * the need for an ERR state. */
		if ( alphabetCovered( st->outRange ) ) {
			/* Pick a default transition by largest span. */
			RedTransAp *defTrans = chooseDefaultSpan( st );

			/* Rewrite the transition list taking out the transition we picked
			 * as the default and store the default. */
			moveToDefault( defTrans, st );
		}
	}
}

RedTransAp *RedFsmAp::chooseDefaultGoto( RedStateAp *state )
{
	/* Make a set of transitions from the outRange. */
	RedTransSet stateTransSet;
	for ( RedTransList::Iter rtel = state->outRange; rtel.lte(); rtel++ ) {
		for ( int c = 0; c < rtel->value->numConds(); c++ ) {
			RedCondPair *cond = rtel->value->outCond(c);
			if ( cond->targ == state->next )
				return rtel->value;
		}
	}
	return 0;
}

void RedFsmAp::chooseDefaultGoto()
{
	/* Loop the states. */
	for ( RedStateList::Iter st = stateList; st.lte(); st++ ) {
		/* Pick a default transition. */
		RedTransAp *defTrans = chooseDefaultGoto( st );
		if ( defTrans == 0 )
			defTrans = chooseDefaultSpan( st );

		/* Rewrite the transition list taking out the transition we picked
		 * as the default and store the default. */
		moveToDefault( defTrans, st );
	}
}

RedTransAp *RedFsmAp::chooseDefaultNumRanges( RedStateAp *state )
{
	/* Make a set of transitions from the outRange. */
	RedTransSet stateTransSet;
	for ( RedTransList::Iter rtel = state->outRange; rtel.lte(); rtel++ )
		stateTransSet.insert( rtel->value );
	
	/* For each transition in the find how many ranges use the transition. */
	int *numRanges = new int[stateTransSet.length()];
	memset( numRanges, 0, sizeof(int) * stateTransSet.length() );
	for ( RedTransList::Iter rtel = state->outRange; rtel.lte(); rtel++ ) {
		/* Lookup the transition in the set. */
		RedTransAp **inSet = stateTransSet.find( rtel->value );
		numRanges[inSet - stateTransSet.data] += 1;
	}

	/* Find the max number of ranges. */
	RedTransAp *maxTrans = 0;
	int maxNumRanges = 0;
	for ( RedTransSet::Iter rtel = stateTransSet; rtel.lte(); rtel++ ) {
		if ( numRanges[rtel.pos()] > maxNumRanges ) {
			maxNumRanges = numRanges[rtel.pos()];
			maxTrans = *rtel;
		}
	}

	delete[] numRanges;
	return maxTrans;
}

void RedFsmAp::chooseDefaultNumRanges()
{
	/* Loop the states. */
	for ( RedStateList::Iter st = stateList; st.lte(); st++ ) {
		/* Pick a default transition. */
		RedTransAp *defTrans = chooseDefaultNumRanges( st );

		/* Rewrite the transition list taking out the transition we picked
		 * as the default and store the default. */
		moveToDefault( defTrans, st );
	}
}

RedCondAp *RedFsmAp::getErrorCond()
{
	return allocateCond( getErrorState(), 0 );
}

RedTransAp *RedFsmAp::getErrorTrans()
{
	return allocateTrans( getErrorState(), 0 );
}

RedStateAp *RedFsmAp::getErrorState()
{
	/* Something went wrong. An error state is needed but one was not supplied
	 * by the frontend. */
	assert( errState != 0 );
	return errState;
}

/* Makes a plain transition. */
RedTransAp *RedFsmAp::allocateTrans( RedStateAp *targ, RedAction *action )
{
	/* Create a reduced trans and look for it in the transiton set. */
	RedTransAp redTrans( 0, 0, targ, action );
	RedTransAp *inDict = transSet.find( &redTrans );
	if ( inDict == 0 ) {
		inDict = new RedTransAp( nextTransId++, nextCondId++, targ, action );
		transSet.insert( inDict );
	}
	return inDict;
}

/* Makes a cond list transition. */
RedTransAp *RedFsmAp::allocateTrans( GenCondSpace *condSpace,
		RedCondEl *outConds, int numConds, RedCondAp *errCond )
{
	/* Create a reduced trans and look for it in the transiton set. */
	RedTransAp redTrans( 0, condSpace, outConds, numConds, errCond );
	RedTransAp *inDict = transSet.find( &redTrans );
	if ( inDict == 0 ) {
		inDict = new RedTransAp( nextTransId++, condSpace, outConds, numConds, errCond );
		transSet.insert( inDict );
	}
	else {
		/* Need to free the out cond vector. */
		delete[] outConds;
	}
	return inDict;
}

RedCondAp *RedFsmAp::allocateCond( RedStateAp *targ, RedAction *action )
{
	/* Create a reduced trans and look for it in the transiton set. */
	RedCondAp redCond( targ, action, 0 );
	RedCondAp *inDict = condSet.find( &redCond );
	if ( inDict == 0 ) {
		inDict = new RedCondAp( targ, action, nextCondId++ );
		condSet.insert( inDict );
	}
	return inDict;
}

void RedFsmAp::partitionFsm( int nparts )
{
	/* At this point the states are ordered by a depth-first traversal. We
	 * will allocate to partitions based on this ordering. */
	this->nParts = nparts;
	int partSize = stateList.length() / nparts;
	int remainder = stateList.length() % nparts;
	int numInPart = partSize;
	int partition = 0;
	if ( remainder-- > 0 )
		numInPart += 1;
	for ( RedStateList::Iter st = stateList; st.lte(); st++ ) {
		st->partition = partition;

		numInPart -= 1;
		if ( numInPart == 0 ) {
			partition += 1;
			numInPart = partSize;
			if ( remainder-- > 0 )
				numInPart += 1;
		}
	}
}

void RedFsmAp::setInTrans()
{
	/* First pass counts the number of transitions. */
	for ( CondApSet::Iter trans = condSet; trans.lte(); trans++ )
		trans->p.targ->numInConds += 1;

	for ( TransApSet::Iter trans = transSet; trans.lte(); trans++ ) {
		if ( trans->condSpace == 0 ) 
			trans->p.targ->numInConds += 1;
		else {
			/* We have a placement choice here, but associate it with the
			 * first. */
			RedCondPair *pair = trans->outCond( 0 );
			pair->targ->numInCondTests += 1;
		}
	}

	/* Allocate. Reset the counts so we can use them as the current size. */
	for ( RedStateList::Iter st = stateList; st.lte(); st++ ) {
		st->inConds = new RedCondPair*[st->numInConds];
		st->numInConds = 0;

		st->inCondTests = new RedTransAp*[st->numInCondTests];
		st->numInCondTests = 0;
	}

	/* Fill the arrays. */
	for ( CondApSet::Iter trans = condSet; trans.lte(); trans++ ) {
		RedStateAp *targ = trans->p.targ;
		targ->inConds[targ->numInConds++] = &trans->p;
	}

	for ( TransApSet::Iter trans = transSet; trans.lte(); trans++ ) {
		if ( trans->condSpace == 0 ) {
			RedStateAp *targ = trans->p.targ;
			targ->inConds[targ->numInConds++] = &trans->p;
		}
		else {
			RedCondPair *pair = trans->outCond( 0 );
			RedStateAp *targ = pair->targ;
			targ->inCondTests[targ->numInCondTests++] = trans;
		}
	}
}

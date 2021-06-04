/*
 * Copyright 2006-2018 Adrian Thurston <thurston@colm.net>
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

#include <assert.h>

#include "fsmgraph.h"

/* Simple singly linked list append routine for the fill list. The new state
 * goes to the end of the list. */
void MergeData::fillListAppend( FsmState *state )
{
	state->alg.next = 0;

	if ( stfillHead == 0 ) {
		/* List is empty, state becomes head and tail. */
		stfillHead = state;
		stfillTail = state;
	}
	else {
		/* List is not empty, state goes after last element. */
		stfillTail->alg.next = state;
		stfillTail = state;
	}
}

/* Graph constructor. */
FsmGraph::FsmGraph()
:
	/* No start state. */
	startState(0),
	errState(0),

	/* Misfit accounting is a switch, turned on only at specific times. It
	 * controls what happens when states have no way in from the outside
	 * world.. */
	misfitAccounting(false),

	lmRequiresErrorState(false)
{
}

/* Copy all graph data including transitions. */
FsmGraph::FsmGraph( const FsmGraph &graph )
:
	/* Lists start empty. Will be filled by copy. */
	stateList(),
	misfitList(),

	/* Copy in the entry points, 
	 * pointers will be resolved later. */
	entryPoints(graph.entryPoints),
	startState(graph.startState),
	errState(0),

	/* Will be filled by copy. */
	finStateSet(),
	
	/* Misfit accounting is only on during merging. */
	misfitAccounting(false),

	lmRequiresErrorState(graph.lmRequiresErrorState)
{
	/* Create the states and record their map in the original state. */
	StateList::Iter origState = graph.stateList;
	for ( ; origState.lte(); origState++ ) {
		/* Make the new state. */
		FsmState *newState = new FsmState( *origState );

		/* Add the state to the list.  */
		stateList.append( newState );

		/* Set the mapsTo item of the old state. */
		origState->alg.stateMap = newState;
	}
	
	/* Derefernce all the state maps. */
	for ( StateList::Iter state = stateList; state.lte(); state++ ) {
		for ( TransList::Iter trans = state->outList; trans.lte(); trans++ ) {
			/* The points to the original in the src machine. The taget's duplicate
			 * is in the statemap. */
			FsmState *toState = trans->toState != 0 ? trans->toState->alg.stateMap : 0;

			/* Attach The transition to the duplicate. */
			trans->toState = 0;
			attachTrans( state, toState, trans );
		}
	}

	/* Fix the state pointers in the entry points array. */
	EntryMapEl *eel = entryPoints.data;
	for ( int e = 0; e < entryPoints.length(); e++, eel++ ) {
		/* Get the duplicate of the state. */
		eel->value = eel->value->alg.stateMap;

		/* Foreign in transitions must be built up when duping machines so
		 * increment it here. */
		eel->value->foreignInTrans += 1;
	}

	/* Fix the start state pointer and the new start state's count of in
	 * transiions. */
	startState = startState->alg.stateMap;
	startState->foreignInTrans += 1;

	/* Build the final state set. */
	StateSet::Iter st = graph.finStateSet; 
	for ( ; st.lte(); st++ ) 
		finStateSet.insert((*st)->alg.stateMap);
}

/* Deletes all transition data then deletes each state. */
FsmGraph::~FsmGraph()
{
	/* Delete all the transitions. */
	for ( StateList::Iter state = stateList; state.lte(); state++ ) {
		/* Iterate the out transitions, deleting them. */
		state->outList.empty();
	}

	/* Delete all the states. */
	stateList.empty();
}

/* Set a state final. The state has its isFinState set to true and the state
 * is added to the finStateSet. */
void FsmGraph::setFinState( FsmState *state )
{
	/* Is it already a fin state. */
	if ( state->stateBits & SB_ISFINAL )
		return;
	
	state->stateBits |= SB_ISFINAL;
	finStateSet.insert( state );
}

/* Set a state non-final. The has its isFinState flag set false and the state
 * is removed from the final state set. */
void FsmGraph::unsetFinState( FsmState *state )
{
	/* Is it already a non-final state? */
	if ( ! (state->stateBits & SB_ISFINAL) )
		return;

	/* When a state looses its final state status it must relinquish all the
	 * properties that are allowed only for final states. */
	clearOutData( state );

	state->stateBits &= ~ SB_ISFINAL;
	finStateSet.remove( state );
}

/* Set and unset a state as the start state. */
void FsmGraph::setStartState( FsmState *state )
{
	/* Sould change from unset to set. */
	assert( startState == 0 );
	startState = state;

	if ( misfitAccounting ) {
		/* If the number of foreign in transitions is about to go up to 1 then
		 * take it off the misfit list and put it on the head list. */
		if ( state->foreignInTrans == 0 )
			stateList.append( misfitList.detach( state ) );
	}

	/* Up the foreign in transitions to the state. */
	state->foreignInTrans += 1;
}

void FsmGraph::unsetStartState()
{
	/* Should change from set to unset. */
	assert( startState != 0 );

	/* Decrement the entry's count of foreign entries. */
	startState->foreignInTrans -= 1;

	if ( misfitAccounting ) {
		/* If the number of foreign in transitions just went down to 0 then take
		 * it off the main list and put it on the misfit list. */
		if ( startState->foreignInTrans == 0 )
			misfitList.append( stateList.detach( startState ) );
	}

	startState = 0;
}

/* Associate an id with a state. Makes the state a named entry point. Has no
 * effect if the entry point is already mapped to the state. */
void FsmGraph::setEntry( int id, FsmState *state )
{
	/* Insert the id into the state. If the state is already labelled with id,
	 * nothing to do. */
	if ( state->entryIds.insert( id ) ) {
		/* Insert the entry and assert that it succeeds. */
		entryPoints.insertMulti( id, state );

		if ( misfitAccounting ) {
			/* If the number of foreign in transitions is about to go up to 1 then
			 * take it off the misfit list and put it on the head list. */
			if ( state->foreignInTrans == 0 )
				stateList.append( misfitList.detach( state ) );
		}

		/* Up the foreign in transitions to the state. */
		state->foreignInTrans += 1;
	}
}

/* Remove the association of an id with a state. The state looses it's entry
 * point status. Assumes that the id is indeed mapped to state. */
void FsmGraph::unsetEntry( int id, FsmState *state )
{
	/* Find the entry point in on id. */
	EntryMapEl *enLow = 0, *enHigh = 0;
	entryPoints.findMulti( id, enLow, enHigh );
	while ( enLow->value != state )
		enLow += 1;

	/* Remove the record from the map. */
	entryPoints.remove( enLow );

	/* Remove the state's sense of the link. */
	state->entryIds.remove( id );
	state->foreignInTrans -= 1;
	if ( misfitAccounting ) {
		/* If the number of foreign in transitions just went down to 0 then take
		 * it off the main list and put it on the misfit list. */
		if ( state->foreignInTrans == 0 )
			misfitList.append( stateList.detach( state ) );
	}
}

/* Remove all association of an id with states. Assumes that the id is indeed
 * mapped to a state. */
void FsmGraph::unsetEntry( int id )
{
	/* Find the entry point in on id. */
	EntryMapEl *enLow = 0, *enHigh = 0;
	entryPoints.findMulti( id, enLow, enHigh );
	for ( EntryMapEl *mel = enLow; mel <= enHigh; mel++ ) {
		/* Remove the state's sense of the link. */
		mel->value->entryIds.remove( id );
		mel->value->foreignInTrans -= 1;
		if ( misfitAccounting ) {
			/* If the number of foreign in transitions just went down to 0
			 * then take it off the main list and put it on the misfit list. */
			if ( mel->value->foreignInTrans == 0 )
				misfitList.append( stateList.detach( mel->value ) );
		}
	}

	/* Remove the records from the entry points map. */
	entryPoints.removeMulti( enLow, enHigh );
}


void FsmGraph::changeEntry( int id, FsmState *to, FsmState *from )
{
	/* Find the entry in the entry map. */
	EntryMapEl *enLow = 0, *enHigh = 0;
	entryPoints.findMulti( id, enLow, enHigh );
	while ( enLow->value != from )
		enLow += 1;
	
	/* Change it to the new target. */
	enLow->value = to;

	/* Remove from's sense of the link. */
	from->entryIds.remove( id );
	from->foreignInTrans -= 1;
	if ( misfitAccounting ) {
		/* If the number of foreign in transitions just went down to 0 then take
		 * it off the main list and put it on the misfit list. */
		if ( from->foreignInTrans == 0 )
			misfitList.append( stateList.detach( from ) );
	}

	/* Add to's sense of the link. */
	if ( to->entryIds.insert( id ) != 0 ) {
		if ( misfitAccounting ) {
			/* If the number of foreign in transitions is about to go up to 1 then
			 * take it off the misfit list and put it on the head list. */
			if ( to->foreignInTrans == 0 )
				stateList.append( misfitList.detach( to ) );
		}

		/* Up the foreign in transitions to the state. */
		to->foreignInTrans += 1;
	}
}


/* Clear all entry points from a machine. */
void FsmGraph::unsetAllEntryPoints()
{
	for ( EntryMap::Iter en = entryPoints; en.lte(); en++ ) {
		/* Kill all the state's entry points at once. */
		if ( en->value->entryIds.length() > 0 ) {
			en->value->foreignInTrans -= en->value->entryIds.length();

			if ( misfitAccounting ) {
				/* If the number of foreign in transitions just went down to 0
				 * then take it off the main list and put it on the misfit
				 * list. */
				if ( en->value->foreignInTrans == 0 )
					misfitList.append( stateList.detach( en->value ) );
			}

			/* Clear the set of ids out all at once. */
			en->value->entryIds.empty();
		}
	}

	/* Now clear out the entry map all at once. */
	entryPoints.empty();
}

/* Assigning an epsilon transition into final states. */
void FsmGraph::epsilonTrans( int id )
{
	for ( StateSet::Iter fs = finStateSet; fs.lte(); fs++ )
		(*fs)->epsilonTrans.append( id );
}

/* Mark all states reachable from state. Traverses transitions forward. Used
 * for removing states that have no path into them. */
void FsmGraph::markReachableFromHere( FsmState *state )
{
	/* Base case: return; */
	if ( state->stateBits & SB_ISMARKED )
		return;
	
	/* Set this state as processed. We are going to visit all states that this
	 * state has a transition to. */
	state->stateBits |= SB_ISMARKED;

	/* Recurse on all out transitions. */
	for ( TransList::Iter trans = state->outList; trans.lte(); trans++ ) {
		if ( trans->toState != 0 )
			markReachableFromHere( trans->toState );
	}
}

void FsmGraph::markReachableFromHereStopFinal( FsmState *state )
{
	/* Base case: return; */
	if ( state->stateBits & SB_ISMARKED )
		return;
	
	/* Set this state as processed. We are going to visit all states that this
	 * state has a transition to. */
	state->stateBits |= SB_ISMARKED;

	/* Recurse on all out transitions. */
	for ( TransList::Iter trans = state->outList; trans.lte(); trans++ ) {
		FsmState *toState = trans->toState;
		if ( toState != 0 && !toState->isFinState() )
			markReachableFromHereStopFinal( toState );
	}
}

/* Mark all states reachable from state. Traverse transitions backwards. Used
 * for removing dead end paths in graphs. */
void FsmGraph::markReachableFromHereReverse( FsmState *state )
{
	/* Base case: return; */
	if ( state->stateBits & SB_ISMARKED )
		return;
	
	/* Set this state as processed. We are going to visit all states with
	 * transitions into this state. */
	state->stateBits |= SB_ISMARKED;

	/* Recurse on all items in transitions. */
	for ( TransInList::Iter trans = state->inList; trans.lte(); trans++ ) 
		markReachableFromHereReverse( trans->fromState );
}

/* Determine if there are any entry points into a start state other than the
 * start state. Setting starting transitions requires that the start state be
 * isolated. In most cases a start state will already be isolated. */
bool FsmGraph::isStartStateIsolated()
{
	/* If there are any in transitions then the state is not isolated. */
	if ( startState->inList.head != 0 )
		return false;

	/* If there are any entry points then isolated. */
	if ( startState->entryIds.length() > 0 )
		return false;

	return true;
}

/* Bring in other's entry points. Assumes others states are going to be
 * copied into this machine. */
void FsmGraph::copyInEntryPoints( FsmGraph *other )
{
	/* Use insert multi because names are not unique. */
	for ( EntryMap::Iter en = other->entryPoints; en.lte(); en++ )
		entryPoints.insertMulti( en->key, en->value );
}


void FsmGraph::unsetAllFinStates()
{
	for ( StateSet::Iter st = finStateSet; st.lte(); st++ )
		(*st)->stateBits &= ~ SB_ISFINAL;
	finStateSet.empty();
}

void FsmGraph::setFinBits( int finStateBits )
{
	for ( int s = 0; s < finStateSet.length(); s++ )
		finStateSet.data[s]->stateBits |= finStateBits;
}


/* Tests the integrity of the transition lists and the fromStates. */
void FsmGraph::verifyIntegrity()
{
	for ( StateList::Iter state = stateList; state.lte(); state++ ) {
		/* Walk the out transitions and assert fromState is correct. */
		for ( TransList::Iter trans = state->outList; trans.lte(); trans++ )
			assert( trans->fromState == state );

		/* Walk the inlist and assert toState is correct. */
		for ( TransInList::Iter trans = state->inList; trans.lte(); trans++ ) 
			assert( trans->toState == state );
	}
}

void FsmGraph::verifyReachability()
{
	/* Mark all the states that can be reached 
	 * through the set of entry points. */
	markReachableFromHere( startState );
	for ( EntryMap::Iter en = entryPoints; en.lte(); en++ )
		markReachableFromHere( en->value );

	/* Check that everything got marked. */
	for ( StateList::Iter st = stateList; st.lte(); st++ ) {
		/* Assert it got marked and then clear the mark. */
		assert( st->stateBits & SB_ISMARKED );
		st->stateBits &= ~ SB_ISMARKED;
	}
}

void FsmGraph::verifyNoDeadEndStates()
{
	/* Mark all states that have paths to the final states. */
	for ( StateSet::Iter pst = finStateSet; pst.lte(); pst++ )
		markReachableFromHereReverse( *pst );

	/* Start state gets honorary marking. Must be done AFTER recursive call. */
	startState->stateBits |= SB_ISMARKED;

	/* Make sure everything got marked. */
	for ( StateList::Iter st = stateList; st.lte(); st++ ) {
		/* Assert the state got marked and unmark it. */
		assert( st->stateBits & SB_ISMARKED );
		st->stateBits &= ~ SB_ISMARKED;
	}
}

void FsmGraph::depthFirstOrdering( FsmState *state )
{
	/* Nothing to do if the state is already on the list. */
	if ( state->stateBits & SB_ONLIST )
		return;

	/* Doing depth first, put state on the list. */
	state->stateBits |= SB_ONLIST;
	stateList.append( state );
	
	/* Recurse on everything ranges. */
	for ( TransList::Iter tel = state->outList; tel.lte(); tel++ ) {
		if ( tel->toState != 0 )
			depthFirstOrdering( tel->toState );
	}
}

/* Ordering states by transition connections. */
void FsmGraph::depthFirstOrdering()
{
	/* Init on state list flags. */
	for ( StateList::Iter st = stateList; st.lte(); st++ )
		st->stateBits &= ~SB_ONLIST;
	
	/* Clear out the state list, we will rebuild it. */
	int stateListLen = stateList.length();
	stateList.abandon();

	/* Add back to the state list from the start state and all other entry
	 * points. */
	if ( errState != 0 )
		depthFirstOrdering( errState );
	depthFirstOrdering( startState );
	for ( EntryMap::Iter en = entryPoints; en.lte(); en++ )
		depthFirstOrdering( en->value );
	
	/* Make sure we put everything back on. */
	assert( stateListLen == stateList.length() );
}

/* Stable sort the states by final state status. */
void FsmGraph::sortStatesByFinal()
{
	/* Move forward through the list and throw final states onto the end. */
	FsmState *state = 0;
	FsmState *next = stateList.head;
	FsmState *last = stateList.tail;
	while ( state != last ) {
		/* Move forward and load up the next. */
		state = next;
		next = state->next;

		/* Throw to the end? */
		if ( state->isFinState() ) {
			stateList.detach( state );
			stateList.append( state );
		}
	}
}

void FsmGraph::setStateNumbers( int base )
{
	for ( StateList::Iter state = stateList; state.lte(); state++ )
		state->alg.stateNum = base++;
}


bool FsmGraph::checkErrTrans( FsmState *state, FsmTrans *trans )
{
	/* Might go directly to error state. */
	if ( trans->toState == 0 )
		return true;

	if ( trans->prev == 0 ) {
		/* If this is the first transition. */
		if ( keyOps->minKey < trans->lowKey )
			return true;
	}
	else {
		/* Not the first transition. Compare against the prev. */
		FsmTrans *prev = trans->prev;
		Key nextKey = prev->highKey;
		nextKey.increment();
		if ( nextKey < trans->lowKey )
			return true; 
	}
	return false;
}

bool FsmGraph::checkErrTransFinish( FsmState *state )
{
	/* Check if there are any ranges already. */
	if ( state->outList.length() == 0 )
		return true;
	else {
		/* Get the last and check for a gap on the end. */
		FsmTrans *last = state->outList.tail;
		if ( last->highKey < keyOps->maxKey )
			return true;
	}
	return 0;
}

bool FsmGraph::hasErrorTrans()
{
	bool result;
	for ( StateList::Iter st = stateList; st.lte(); st++ ) {
		for ( TransList::Iter tr = st->outList; tr.lte(); tr++ ) {
			result = checkErrTrans( st, tr );
			if ( result )
				return true;
		}
		result = checkErrTransFinish( st );
		if ( result )
			return true;
	}
	return false;
}

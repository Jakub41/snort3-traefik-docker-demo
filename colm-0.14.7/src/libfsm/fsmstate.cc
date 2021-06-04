/*
 * Copyright 2002-2018 Adrian Thurston <thurston@colm.net>
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

#include "fsmgraph.h"

#include <string.h>
#include <assert.h>
#include <iostream>

/* Construct a mark index for a specified number of states. Must new up
 * an array that is states^2 in size. */
MarkIndex::MarkIndex( int states ) : numStates(states)
{
	/* Total pairs is states^2. Actually only use half of these, but we allocate
	 * them all to make indexing into the array easier. */
	int total = states * states;

	/* New up chars so that individual DListEl constructors are
	 * not called. Zero out the mem manually. */
	array = new bool[total];
	memset( array, 0, sizeof(bool) * total );
}

/* Free the array used to store state pairs. */
MarkIndex::~MarkIndex()
{
	delete[] array;
}

/* Mark a pair of states. States are specified by their number. The
 * marked states are moved from the unmarked list to the marked list. */
void MarkIndex::markPair(int state1, int state2)
{
	int pos = ( state1 >= state2 ) ?
		( state1 * numStates ) + state2 :
		( state2 * numStates ) + state1;

	array[pos] = true;
}

/* Returns true if the pair of states are marked. Returns false otherwise.
 * Ordering of states given does not matter. */
bool MarkIndex::isPairMarked(int state1, int state2)
{
	int pos = ( state1 >= state2 ) ?
		( state1 * numStates ) + state2 :
		( state2 * numStates ) + state1;

	return array[pos];
}

/* Create a new fsm state. State has not out transitions or in transitions, not
 * out out transition data and not number. */
StateAp::StateAp()
:
	/* No out or in transitions. */
	outList(),
	inTrans(),
	inCond(),

	/* No EOF target. */
	eofTarget(0),

	/* No entry points, or epsilon trans. */
	entryIds(),
	epsilonTrans(),

	/* No transitions in from other states. */
	foreignInTrans(0),

	/* Only used during merging. Normally null. */
	stateDictEl(0),
	stateDictIn(0),

	nfaOut(0),
	nfaIn(0),

	eptVect(0),

	/* No state identification bits. */
	stateBits(0),

	/* No Priority data. */
	outPriorTable(),

	/* No Action data. */
	toStateActionTable(),
	fromStateActionTable(),
	outActionTable(),
	outCondSpace(0),
	outCondKeys(),
	errActionTable(),
	eofActionTable(),
	guardedInTable(),
	lmNfaParts()
{
}

/* Copy everything except actual the transitions. That is left up to the
 * FsmAp copy constructor. */
StateAp::StateAp(const StateAp &other)
:
	/* All lists are cleared. They will be filled in when the
	 * individual transitions are duplicated and attached. */
	outList(),
	inTrans(),
	inCond(),

	/* Set this using the original state's eofTarget. It will get mapped back
	 * to the new machine in the Fsm copy constructor. */
	eofTarget(other.eofTarget),

	/* Duplicate the entry id set and epsilon transitions. These
	 * are sets of integers and as such need no fixing. */
	entryIds(other.entryIds),
	epsilonTrans(other.epsilonTrans),

	/* No transitions in from other states. */
	foreignInTrans(0),

	/* This is only used during merging. Normally null. */
	stateDictEl(0),
	stateDictIn(0),

	nfaOut(0),
	nfaIn(0),

	eptVect(0),

	/* Fsm state data. */
	stateBits(other.stateBits),

	/* Copy in priority data. */
	outPriorTable(other.outPriorTable),

	/* Copy in action data. */
	toStateActionTable(other.toStateActionTable),
	fromStateActionTable(other.fromStateActionTable),
	outActionTable(other.outActionTable),
	outCondSpace(other.outCondSpace),
	outCondKeys(other.outCondKeys),
	errActionTable(other.errActionTable),
	eofActionTable(other.eofActionTable),

	guardedInTable(other.guardedInTable),
	lmNfaParts(other.lmNfaParts)
{
	/* Duplicate all the transitions. */
	for ( TransList::Iter trans = other.outList; trans.lte(); trans++ ) {
		if ( trans->plain() ) {
			/* Duplicate and store the orginal target in the transition. This will
			 * be corrected once all the states have been created. */
			TransDataAp *newTrans = new TransDataAp( *trans->tdap() );
			assert( trans->tdap()->lmActionTable.length() == 0 );
			newTrans->toState = trans->tdap()->toState;
			outList.append( newTrans );
		}
		else {
			/* Duplicate and store the orginal target in the transition. This will
			 * be corrected once all the states have been created. */
			TransAp *newTrans = new TransCondAp( *trans->tcap() );

			for ( CondList::Iter cti = trans->tcap()->condList; cti.lte(); cti++ ) {
				CondAp *newCondTrans = new CondAp( *cti, newTrans );
				newCondTrans->key = cti->key;

				newTrans->tcap()->condList.append( newCondTrans );

				assert( cti->lmActionTable.length() == 0 );

				newCondTrans->toState = cti->toState;
			}

			outList.append( newTrans );
		}
	}

	/* Dup the nfa trans. */
	if ( other.nfaOut != 0 ) {
		nfaOut = new NfaTransList;
		for ( NfaTransList::Iter trans = *other.nfaOut; trans.lte(); trans++ ) {
			NfaTrans *newtrans = new NfaTrans( *trans );
			newtrans->toState = trans->toState;

			nfaOut->append( newtrans );
		}
	}
}

/* If there is a state dict element, then delete it. Everything else is left
 * up to the FsmGraph destructor. */
StateAp::~StateAp()
{
	if ( stateDictEl != 0 )
		delete stateDictEl;

	if ( stateDictIn != 0 )
		delete stateDictIn;

	if ( nfaIn != 0 )
		delete nfaIn;

	if ( nfaOut != 0 ) {
		nfaOut->empty();
		delete nfaOut;
	}
}

#ifdef TO_UPGRADE_CONDS
/* Compare two states using pointers to the states. With the approximate
 * compare, the idea is that if the compare finds them the same, they can
 * immediately be merged. */
int ApproxCompare::compare( const StateAp *state1, const StateAp *state2 )
{
	int compareRes;

	/* Test final state status. */
	if ( (state1->stateBits & STB_ISFINAL) && !(state2->stateBits & STB_ISFINAL) )
		return -1;
	else if ( !(state1->stateBits & STB_ISFINAL) && (state2->stateBits & STB_ISFINAL) )
		return 1;
	
	/* Test epsilon transition sets. */
	compareRes = CmpEpsilonTrans::compare( state1->epsilonTrans, 
			state2->epsilonTrans );
	if ( compareRes != 0 )
		return compareRes;
	
	/* Compare the out transitions. */
	compareRes = FsmAp::compareStateData( state1, state2 );
	if ( compareRes != 0 )
		return compareRes;

	/* Use a pair iterator to get the transition pairs. */
	RangePairIter<TransAp> outPair( ctx, state1->outList.head, state2->outList.head );
	for ( ; !outPair.end(); outPair++ ) {
		switch ( outPair.userState ) {

		case RangePairIter<TransAp>::RangeInS1:
			compareRes = FsmAp::compareFullPtr( outPair.s1Tel.trans, 0 );
			if ( compareRes != 0 )
				return compareRes;
			break;

		case RangePairIter<TransAp>::RangeInS2:
			compareRes = FsmAp::compareFullPtr( 0, outPair.s2Tel.trans );
			if ( compareRes != 0 )
				return compareRes;
			break;

		case RangePairIter<TransAp>::RangeOverlap:
			compareRes = FsmAp::compareFullPtr( 
					outPair.s1Tel.trans, outPair.s2Tel.trans );
			if ( compareRes != 0 )
				return compareRes;
			break;

		case RangePairIter<TransAp>::BreakS1:
		case RangePairIter<TransAp>::BreakS2:
			break;
		}
	}

	/* Check EOF targets. */
	if ( state1->eofTarget < state2->eofTarget )
		return -1;
	else if ( state1->eofTarget > state2->eofTarget )
		return 1;
	
	if ( state1->guardedIn || !state2->guardedIn )
		return -1;
	else if ( !state1->guardedIn || state2->guardedIn )
		return 1;

	/* Got through the entire state comparison, deem them equal. */
	return 0;
}
#endif


/* Compare class used in the initial partition. */
int InitPartitionCompare::compare( const StateAp *state1, const StateAp *state2 )
{
	int compareRes;

	if ( state1->nfaOut == 0 && state2->nfaOut != 0 )
		return -1;
	else if ( state1->nfaOut != 0 && state2->nfaOut == 0 )
		return 1;
	else if ( state1->nfaOut != 0 ) {
		compareRes = CmpNfaTransList::compare(
				*state1->nfaOut, *state2->nfaOut );
		if ( compareRes != 0 )
			return compareRes;
	}

	/* Test final state status. */
	if ( (state1->stateBits & STB_ISFINAL) && !(state2->stateBits & STB_ISFINAL) )
		return -1;
	else if ( !(state1->stateBits & STB_ISFINAL) && (state2->stateBits & STB_ISFINAL) )
		return 1;

	/* Test epsilon transition sets. */
	compareRes = CmpEpsilonTrans::compare( state1->epsilonTrans, 
			state2->epsilonTrans );
	if ( compareRes != 0 )
		return compareRes;

	/* Compare the out transitions. */
	compareRes = FsmAp::compareStateData( state1, state2 );
	if ( compareRes != 0 )
		return compareRes;

	/* Use a pair iterator to test the transition pairs. */
	typedef RangePairIter< PiList<TransAp> > RangePairIterPiListTransAp;
	RangePairIterPiListTransAp
		outPair( ctx, state1->outList, state2->outList );
	for ( ; !outPair.end(); outPair++ ) {
		switch ( outPair.userState ) {

		case RangePairIterPiListTransAp::RangeInS1:
			compareRes = FsmAp::compareTransDataPtr( outPair.s1Tel.trans, 0 );
			if ( compareRes != 0 )
				return compareRes;
			break;

		case RangePairIterPiListTransAp::RangeInS2:
			compareRes = FsmAp::compareTransDataPtr( 0, outPair.s2Tel.trans );
			if ( compareRes != 0 )
				return compareRes;
			break;

		case RangePairIterPiListTransAp::RangeOverlap:
			compareRes = FsmAp::compareTransDataPtr( 
					outPair.s1Tel.trans, outPair.s2Tel.trans );
			if ( compareRes != 0 )
				return compareRes;
			break;

		case RangePairIterPiListTransAp::BreakS1:
		case RangePairIterPiListTransAp::BreakS2:
			break;
		}
	}

	return 0;
}

/* Compare class for the sort that does the partitioning. */
int PartitionCompare::compare( const StateAp *state1, const StateAp *state2 )
{
	int compareRes;

	/* Use a pair iterator to get the transition pairs. */
	typedef RangePairIter< PiList<TransAp> > RangePairIterPiListTransAp;
	RangePairIterPiListTransAp outPair( ctx, state1->outList, state2->outList );
	for ( ; !outPair.end(); outPair++ ) {
		switch ( outPair.userState ) {

		case RangePairIterPiListTransAp::RangeInS1:
			compareRes = FsmAp::compareTransPartPtr( outPair.s1Tel.trans, 0 );
			if ( compareRes != 0 )
				return compareRes;
			break;

		case RangePairIterPiListTransAp::RangeInS2:
			compareRes = FsmAp::compareTransPartPtr( 0, outPair.s2Tel.trans );
			if ( compareRes != 0 )
				return compareRes;
			break;

		case RangePairIterPiListTransAp::RangeOverlap:
			compareRes = FsmAp::compareTransPartPtr( 
					outPair.s1Tel.trans, outPair.s2Tel.trans );
			if ( compareRes != 0 )
				return compareRes;
			break;

		case RangePairIterPiListTransAp::BreakS1:
		case RangePairIterPiListTransAp::BreakS2:
			break;
		}
	}

	/* Test eof targets. */
	if ( state1->eofTarget == 0 && state2->eofTarget != 0 )
		return -1;
	else if ( state1->eofTarget != 0 && state2->eofTarget == 0 )
		return 1;
	else if ( state1->eofTarget != 0 ) {
		/* Both eof targets are set. */
		compareRes = CmpOrd< MinPartition* >::compare( 
			state1->eofTarget->alg.partition, state2->eofTarget->alg.partition );
		if ( compareRes != 0 )
			return compareRes;
	}

	return 0;
}

#ifdef TO_UPGRADE_CONDS
/* Compare class for the sort that does the partitioning. */
bool MarkCompare::shouldMark( MarkIndex &markIndex, const StateAp *state1, 
			const StateAp *state2 )
{
	/* Use a pair iterator to get the transition pairs. */
	RangePairIter<TransAp> outPair( ctx, state1->outList.head, state2->outList.head );
	for ( ; !outPair.end(); outPair++ ) {
		switch ( outPair.userState ) {

		case RangePairIter<TransAp>::RangeInS1:
			if ( FsmAp::shouldMarkPtr( markIndex, outPair.s1Tel.trans, 0 ) )
				return true;
			break;

		case RangePairIter<TransAp>::RangeInS2:
			if ( FsmAp::shouldMarkPtr( markIndex, 0, outPair.s2Tel.trans ) )
				return true;
			break;

		case RangePairIter<TransAp>::RangeOverlap:
			if ( FsmAp::shouldMarkPtr( markIndex,
					outPair.s1Tel.trans, outPair.s2Tel.trans ) )
				return true;
			break;

		case RangePairIter<TransAp>::BreakS1:
		case RangePairIter<TransAp>::BreakS2:
			break;
		}
	}

	return false;
}
#endif

/*
 * Transition Comparison.
 */

int FsmAp::comparePart( TransAp *trans1, TransAp *trans2 )
{
	if ( trans1->plain() ) {
		int compareRes = FsmAp::compareCondPartPtr( trans1->tdap(), trans2->tdap() );
		if ( compareRes != 0 )
			return compareRes;
	}
	else { 
		/* Use a pair iterator to get the transition pairs. */
		typedef ValPairIter< PiList<CondAp> > ValPairIterPiListCondAp;
		ValPairIterPiListCondAp outPair( trans1->tcap()->condList,
				trans2->tcap()->condList );
		for ( ; !outPair.end(); outPair++ ) {
			switch ( outPair.userState ) {

			case ValPairIterPiListCondAp::RangeInS1: {
				int compareRes = FsmAp::compareCondPartPtr<CondAp>( outPair.s1Tel.trans, 0 );
				if ( compareRes != 0 )
					return compareRes;
				break;
			}

			case ValPairIterPiListCondAp::RangeInS2: {
				int compareRes = FsmAp::compareCondPartPtr<CondAp>( 0, outPair.s2Tel.trans );
				if ( compareRes != 0 )
					return compareRes;
				break;
			}

			case ValPairIterPiListCondAp::RangeOverlap: {
				int compareRes = FsmAp::compareCondPartPtr<CondAp>( 
						outPair.s1Tel.trans, outPair.s2Tel.trans );
				if ( compareRes != 0 )
					return compareRes;
				break;
			}}
		}
	}

	return 0;
}

/* Compare target partitions. Either pointer may be null. */
int FsmAp::compareTransPartPtr( TransAp *trans1, TransAp *trans2 )
{
	if ( trans1 != 0 ) {
		/* If trans1 is set then so should trans2. The initial partitioning
		 * guarantees this for us. */
		return comparePart( trans1, trans2 );
	}

	return 0;
}

template< class Trans > int FsmAp::compareCondPartPtr( Trans *trans1, Trans *trans2 )
{
	if ( trans1 != 0 ) {
		/* If trans1 is set then so should trans2. The initial partitioning
		 * guarantees this for us. */
		if ( trans1->toState == 0 && trans2->toState != 0 )
			return -1;
		else if ( trans1->toState != 0 && trans2->toState == 0 )
			return 1;
		else if ( trans1->toState != 0 ) {
			/* Both of targets are set. */
			return CmpOrd< MinPartition* >::compare( 
				trans1->toState->alg.partition, trans2->toState->alg.partition );
		}
	}
	return 0;
}


/* Compares two transition pointers according to priority and functions.
 * Either pointer may be null. Does not consider to state or from state. */
int FsmAp::compareTransDataPtr( TransAp *trans1, TransAp *trans2 )
{
	if ( trans1 == 0 && trans2 != 0 )
		return -1;
	else if ( trans1 != 0 && trans2 == 0 )
		return 1;
	else if ( trans1 != 0 ) {
		/* Both of the transition pointers are set. */
		int compareRes = compareTransData( trans1, trans2 );
		if ( compareRes != 0 )
			return compareRes;
	}
	return 0;
}

#ifdef TO_UPGRADE_CONDS
/* Compares two transitions according to target state, priority and functions.
 * Does not consider from state. Either of the pointers may be null. */
int FsmAp::compareFullPtr( TransAp *trans1, TransAp *trans2 )
{
	/* << "FIXME: " << __PRETTY_FUNCTION__ << std::endl; */

	if ( (trans1 != 0) ^ (trans2 != 0) ) {
		/* Exactly one of the transitions is set. */
		if ( trans1 != 0 )
			return -1;
		else
			return 1;
	}
	else if ( trans1 != 0 ) {
		/* Both of the transition pointers are set. Test target state,
		 * priority and funcs. */
		if ( tai(trans1)->tcap()->condList.head->toState < tai(trans2)->tcap()->condList.head->toState )
			return -1;
		else if ( tai(trans1)->tcap()->condList.head->toState > tai(trans2)->tcap()->condList.head->toState )
			return 1;
		else if ( tai(trans1)->tcap()->condList.head->toState != 0 ) {
			/* Test transition data. */
			int compareRes = compareTransData( trans1, trans2 );
			if ( compareRes != 0 )
				return compareRes;
		}
	}
	return 0;
}
#endif

#ifdef TO_UPGRADE_CONDS
bool FsmAp::shouldMarkPtr( MarkIndex &markIndex, TransAp *trans1, 
				TransAp *trans2 )
{
	/* << "FIXME: " << __PRETTY_FUNCTION__ << std::endl; */

	if ( (trans1 != 0) ^ (trans2 != 0) ) {
		/* Exactly one of the transitions is set. The initial mark round
		 * should rule out this case. */
		assert( false );
	}
	else if ( trans1 != 0 ) {
		/* Both of the transitions are set. If the target pair is marked, then
		 * the pair we are considering gets marked. */
		return markIndex.isPairMarked( tai(trans1)->tcap()->condList.head->toState->alg.stateNum, 
				tai(trans2)->tcap()->condList.head->toState->alg.stateNum );
	}

	/* Neither of the transitiosn are set. */
	return false;
}
#endif

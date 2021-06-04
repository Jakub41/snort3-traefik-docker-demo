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
#include "mergesort.h"

struct MergeSortInitPartition
	: public MergeSort<StateAp*, InitPartitionCompare>
{
	MergeSortInitPartition( FsmCtx *ctx )
	{
		InitPartitionCompare::ctx = ctx;
	}
};

struct MergeSortPartition
	: public MergeSort<StateAp*, PartitionCompare>
{
	MergeSortPartition( FsmCtx *ctx )
	{
		PartitionCompare::ctx = ctx;
	}
};

struct MergeSortApprox
	: public MergeSort<StateAp*, ApproxCompare>
{
	MergeSortApprox( FsmCtx *ctx )
	{
		ApproxCompare::ctx = ctx;
	}
};

int FsmAp::partitionRound( StateAp **statePtrs, MinPartition *parts, int numParts )
{
	/* Need a mergesort object and a single partition compare. */
	MergeSortPartition mergeSort( ctx );
	PartitionCompare partCompare;

	/* For each partition. */
	for ( int p = 0; p < numParts; p++ ) {
		/* Fill the pointer array with the states in the partition. */
		StateList::Iter state = parts[p].list;
		for ( int s = 0; state.lte(); state++, s++ )
			statePtrs[s] = state;

		/* Sort the states using the partitioning compare. */
		int numStates = parts[p].list.length();
		mergeSort.sort( statePtrs, numStates );

		/* Assign the states into partitions based on the results of the sort. */
		int destPart = p, firstNewPart = numParts;
		for ( int s = 1; s < numStates; s++ ) {
			/* If this state differs from the last then move to the next partition. */
			if ( partCompare.compare( statePtrs[s-1], statePtrs[s] ) < 0 ) {
				/* The new partition is the next avail spot. */
				destPart = numParts;
				numParts += 1;
			}

			/* If the state is not staying in the first partition, then
			 * transfer it to its destination partition. */
			if ( destPart != p ) {
				StateAp *state = parts[p].list.detach( statePtrs[s] );
				parts[destPart].list.append( state );
			}
		}

		/* Fix the partition pointer for all the states that got moved to a new
		 * partition. This must be done after the states are transfered so the
		 * result of the sort is not altered. */
		for ( int newPart = firstNewPart; newPart < numParts; newPart++ ) {
			StateList::Iter state = parts[newPart].list;
			for ( ; state.lte(); state++ )
				state->alg.partition = &parts[newPart];
		}
	}

	return numParts;
}

/**
 * \brief Minimize by partitioning version 1.
 *
 * Repeatedly tries to split partitions until all partitions are unsplittable.
 * Produces the most minimal FSM possible.
 */
void FsmAp::minimizePartition1()
{
	/* Need one mergesort object and partition compares. */
	MergeSortInitPartition mergeSort( ctx );
	InitPartitionCompare initPartCompare( ctx );

	/* Nothing to do if there are no states. */
	if ( stateList.length() == 0 )
		return;

	/* 
	 * First thing is to partition the states by final state status and
	 * transition functions. This gives us an initial partitioning to work
	 * with.
	 */

	/* Make a array of pointers to states. */
	int numStates = stateList.length();
	StateAp** statePtrs = new StateAp*[numStates];

	/* Fill up an array of pointers to the states for easy sorting. */
	StateList::Iter state = stateList;
	for ( int s = 0; state.lte(); state++, s++ )
		statePtrs[s] = state;
		
	/* Sort the states using the array of states. */
	mergeSort.sort( statePtrs, numStates );

	/* An array of lists of states is used to partition the states. */
	MinPartition *parts = new MinPartition[numStates];

	/* Assign the states into partitions. */
	int destPart = 0;
	for ( int s = 0; s < numStates; s++ ) {
		/* If this state differs from the last then move to the next partition. */
		if ( s > 0 && initPartCompare.compare( statePtrs[s-1], statePtrs[s] ) < 0 ) {
			/* Move to the next partition. */
			destPart += 1;
		}

		/* Put the state into its partition. */
		statePtrs[s]->alg.partition = &parts[destPart];
		parts[destPart].list.append( statePtrs[s] );
	}

	/* We just moved all the states from the main list into partitions without
	 * taking them off the main list. So clean up the main list now. */
	stateList.abandon();

	/* Split partitions. */
	int numParts = destPart + 1;
	while ( true ) {
		/* Test all partitions for splitting. */
		int newNum = partitionRound( statePtrs, parts, numParts );

		/* When no partitions can be split, stop. */
		if ( newNum == numParts )
			break;

		numParts = newNum;
	}

	/* Fuse states in the same partition. The states will end up back on the
	 * main list. */
	fusePartitions( parts, numParts );

	/* Cleanup. */
	delete[] statePtrs;
	delete[] parts;
}

/* Split partitions that need splittting, decide which partitions might need
 * to be split as a result, continue until there are no more that might need
 * to be split. */
int FsmAp::splitCandidates( StateAp **statePtrs, MinPartition *parts, int numParts )
{
	/* Need a mergesort and a partition compare. */
	MergeSortPartition mergeSort( ctx );
	PartitionCompare partCompare( ctx );

	/* The lists of unsplitable (partList) and splitable partitions. 
	 * Only partitions in the splitable list are check for needing splitting. */
	PartitionList partList, splittable;

	/* Initially, all partitions are born from a split (the initial
	 * partitioning) and can cause other partitions to be split. So any
	 * partition with a state with a transition out to another partition is a
	 * candidate for splitting. This will make every partition except possibly
	 * partitions of final states split candidates. */
	for ( int p = 0; p < numParts; p++ ) {
		/* Assume not active. */
		parts[p].active = false;

		/* Look for a trans out of any state in the partition. */
		for ( StateList::Iter state = parts[p].list; state.lte(); state++ ) {
			/* If there is at least one transition out to another state then 
			 * the partition becomes splittable. */
			if ( state->outList.length() > 0 ) {
				parts[p].active = true;
				break;
			}
		}

		/* If it was found active then it goes on the splittable list. */
		if ( parts[p].active )
			splittable.append( &parts[p] );
		else
			partList.append( &parts[p] );
	}

	/* While there are partitions that are splittable, pull one off and try
	 * to split it. If it splits, determine which partitions may now be split
	 * as a result of the newly split partition. */
	while ( splittable.length() > 0 ) {
		MinPartition *partition = splittable.detachFirst();

		/* Fill the pointer array with the states in the partition. */
		StateList::Iter state = partition->list;
		for ( int s = 0; state.lte(); state++, s++ )
			statePtrs[s] = state;

		/* Sort the states using the partitioning compare. */
		int numStates = partition->list.length();
		mergeSort.sort( statePtrs, numStates );

		/* Assign the states into partitions based on the results of the sort. */
		MinPartition *destPart = partition;
		int firstNewPart = numParts;
		for ( int s = 1; s < numStates; s++ ) {
			/* If this state differs from the last then move to the next partition. */
			if ( partCompare.compare( statePtrs[s-1], statePtrs[s] ) < 0 ) {
				/* The new partition is the next avail spot. */
				destPart = &parts[numParts];
				numParts += 1;
			}

			/* If the state is not staying in the first partition, then
			 * transfer it to its destination partition. */
			if ( destPart != partition ) {
				StateAp *state = partition->list.detach( statePtrs[s] );
				destPart->list.append( state );
			}
		}

		/* Fix the partition pointer for all the states that got moved to a new
		 * partition. This must be done after the states are transfered so the
		 * result of the sort is not altered. */
		int newPart;
		for ( newPart = firstNewPart; newPart < numParts; newPart++ ) {
			StateList::Iter state = parts[newPart].list;
			for ( ; state.lte(); state++ )
				state->alg.partition = &parts[newPart];
		}

		/* Put the partition we just split and any new partitions that came out
		 * of the split onto the inactive list. */
		partition->active = false;
		partList.append( partition );
		for ( newPart = firstNewPart; newPart < numParts; newPart++ ) {
			parts[newPart].active = false;
			partList.append( &parts[newPart] );
		}

		if ( destPart == partition )
			continue;

		/* Now determine which partitions are splittable as a result of
		 * splitting partition by walking the in lists of the states in
		 * partitions that got split. Partition is the faked first item in the
		 * loop. */
		MinPartition *causalPart = partition;
		newPart = firstNewPart - 1;
		while ( newPart < numParts ) {
			/* Loop all states in the causal partition. */
			StateList::Iter state = causalPart->list;
			for ( ; state.lte(); state++ ) {
				/* Walk all transition into the state and put the partition
				 * that the from state is in onto the splittable list. */
				for ( TransInList::Iter t = state->inTrans; t.lte(); t++ ) {
					MinPartition *fromPart = t->fromState->alg.partition;
					if ( ! fromPart->active ) {
						fromPart->active = true;
						partList.detach( fromPart );
						splittable.append( fromPart );
					}
				}
				for ( CondInList::Iter t = state->inCond; t.lte(); t++ ) {
					MinPartition *fromPart = t->fromState->alg.partition;
					if ( ! fromPart->active ) {
						fromPart->active = true;
						partList.detach( fromPart );
						splittable.append( fromPart );
					}
				}
			}

			newPart += 1;
			causalPart = &parts[newPart];
		}
	}
	return numParts;
}


/**
 * \brief Minimize by partitioning version 2 (best alg).
 *
 * Repeatedly tries to split partitions that may splittable until there are no
 * more partitions that might possibly need splitting. Runs faster than
 * version 1. Produces the most minimal fsm possible.
 */
void FsmAp::minimizePartition2()
{
	/* Need a mergesort and an initial partition compare. */
	MergeSortInitPartition mergeSort( ctx );
	InitPartitionCompare initPartCompare( ctx );

	/* Nothing to do if there are no states. */
	if ( stateList.length() == 0 )
		return;

	/* 
	 * First thing is to partition the states by final state status and
	 * transition functions. This gives us an initial partitioning to work
	 * with.
	 */

	/* Make a array of pointers to states. */
	int numStates = stateList.length();
	StateAp** statePtrs = new StateAp*[numStates];

	/* Fill up an array of pointers to the states for easy sorting. */
	StateList::Iter state = stateList;
	for ( int s = 0; state.lte(); state++, s++ )
		statePtrs[s] = state;
		
	/* Sort the states using the array of states. */
	mergeSort.sort( statePtrs, numStates );

	/* An array of lists of states is used to partition the states. */
	MinPartition *parts = new MinPartition[numStates];

	/* Assign the states into partitions. */
	int destPart = 0;
	for ( int s = 0; s < numStates; s++ ) {
		/* If this state differs from the last then move to the next partition. */
		if ( s > 0 && initPartCompare.compare( statePtrs[s-1], statePtrs[s] ) < 0 ) {
			/* Move to the next partition. */
			destPart += 1;
		}

		/* Put the state into its partition. */
		statePtrs[s]->alg.partition = &parts[destPart];
		parts[destPart].list.append( statePtrs[s] );
	}

	/* We just moved all the states from the main list into partitions without
	 * taking them off the main list. So clean up the main list now. */
	stateList.abandon();

	/* Split partitions. */
	int numParts = splitCandidates( statePtrs, parts, destPart+1 );

	/* Fuse states in the same partition. The states will end up back on the
	 * main list. */
	fusePartitions( parts, numParts );

	/* Cleanup. */
	delete[] statePtrs;
	delete[] parts;
}

void FsmAp::initialMarkRound( MarkIndex &markIndex )
{
	/* P and q for walking pairs. */
	StateAp *p = stateList.head, *q;

	/* Need an initial partition compare. */
	InitPartitionCompare initPartCompare( ctx );

	/* Walk all unordered pairs of (p, q) where p != q.
	 * The second depth of the walk stops before reaching p. This
	 * gives us all unordered pairs of states (p, q) where p != q. */
	while ( p != 0 ) {
		q = stateList.head;
		while ( q != p ) {
			/* If the states differ on final state status, out transitions or
			 * any transition data then they should be separated on the initial
			 * round. */
			if ( initPartCompare.compare( p, q ) != 0 )
				markIndex.markPair( p->alg.stateNum, q->alg.stateNum );

			q = q->next;
		}
		p = p->next;
	}
}

#ifdef TO_UPGRADE_CONDS
bool FsmAp::markRound( MarkIndex &markIndex )
{
	/* P an q for walking pairs. Take note if any pair gets marked. */
	StateAp *p = stateList.head, *q;
	bool pairWasMarked = false;

	/* Need a mark comparison. */
	MarkCompare markCompare( ctx );

	/* Walk all unordered pairs of (p, q) where p != q.
	 * The second depth of the walk stops before reaching p. This
	 * gives us all unordered pairs of states (p, q) where p != q. */
	while ( p != 0 ) {
		q = stateList.head;
		while ( q != p ) {
			/* Should we mark the pair? */
			if ( !markIndex.isPairMarked( p->alg.stateNum, q->alg.stateNum ) ) {
				if ( markCompare.shouldMark( markIndex, p, q ) ) {
					markIndex.markPair( p->alg.stateNum, q->alg.stateNum );
					pairWasMarked = true;
				}
			}
			q = q->next;
		}
		p = p->next;
	}

	return pairWasMarked;
}
#endif

#ifdef TO_UPGRADE_CONDS
/**
 * \brief Minimize by pair marking.
 *
 * Decides if each pair of states is distinct or not. Uses O(n^2) memory and
 * should only be used on small graphs. Produces the most minmimal FSM
 * possible.
 */
void FsmAp::minimizeStable()
{
	/* Set the state numbers. */
	setStateNumbers( 0 );

	/* This keeps track of which pairs have been marked. */
	MarkIndex markIndex( stateList.length() );

	/* Mark pairs where final stateness, out trans, or trans data differ. */
	initialMarkRound( markIndex );

	/* While the last round of marking succeeded in marking a state
	 * continue to do another round. */
	int modified = markRound( markIndex );
	while (modified)
		modified = markRound( markIndex );

	/* Merge pairs that are unmarked. */
	fuseUnmarkedPairs( markIndex );
}
#endif

#ifdef TO_UPGRADE_CONDS
bool FsmAp::minimizeRound()
{
	/* Nothing to do if there are no states. */
	if ( stateList.length() == 0 )
		return false;

	/* Need a mergesort on approx compare and an approx compare. */
	MergeSortApprox mergeSort( ctx );
	ApproxCompare approxCompare( ctx );

	/* Fill up an array of pointers to the states. */
	StateAp **statePtrs = new StateAp*[stateList.length()];
	StateList::Iter state = stateList;
	for ( int s = 0; state.lte(); state++, s++ )
		statePtrs[s] = state;

	bool modified = false;

	/* Sort The list. */
	mergeSort.sort( statePtrs, stateList.length() );

	/* Walk the list looking for duplicates next to each other, 
	 * merge in any duplicates. */
	StateAp **pLast = statePtrs;
	StateAp **pState = statePtrs + 1;
	for ( int i = 1; i < stateList.length(); i++, pState++ ) {
		if ( approxCompare.compare( *pLast, *pState ) == 0 ) {
			/* Last and pState are the same, so fuse together. Move forward
			 * with pState but not with pLast. If any more are identical, we
			 * must */
			fuseEquivStates( *pLast, *pState );
			modified = true;
		}
		else {
			/* Last and this are different, do not set to merge them. Move
			 * pLast to the current (it may be way behind from merging many
			 * states) and pState forward one to consider the next pair. */
			pLast = pState;
		}
	}
	delete[] statePtrs;
	return modified;
}
#endif

#ifdef TO_UPGRADE_CONDS
/**
 * \brief Minmimize by an approximation.
 *
 * Repeatedly tries to find states with transitions out to the same set of
 * states on the same set of keys until no more identical states can be found.
 * Does not produce the most minimial FSM possible.
 */
void FsmAp::minimizeApproximate()
{
	/* While the last minimization round succeeded in compacting states,
	 * continue to try to compact states. */
	while ( true ) {
		bool modified = minimizeRound();
		if ( ! modified )
			break;
	}
}
#endif


/* Remove states that have no path to them from the start state. Recursively
 * traverses the graph marking states that have paths into them. Then removes
 * all states that did not get marked. */
long FsmAp::removeUnreachableStates()
{
	long origLen = stateList.length();

	/* Misfit accounting should be off and there should be no states on the
	 * misfit list. */
	assert( !misfitAccounting && misfitList.length() == 0 );

	/* Mark all the states that can be reached 
	 * through the existing set of entry points. */
	markReachableFromHere( startState );
	for ( EntryMap::Iter en = entryPoints; en.lte(); en++ )
		markReachableFromHere( en->value );

	/* Delete all states that are not marked
	 * and unmark the ones that are marked. */
	StateAp *state = stateList.head;
	while ( state ) {
		StateAp *next = state->next;

		if ( state->stateBits & STB_ISMARKED )
			state->stateBits &= ~ STB_ISMARKED;
		else {
			detachState( state );
			stateList.detach( state );
			delete state;
		}

		state = next;
	}

	return origLen - stateList.length();
}

bool FsmAp::outListCovers( StateAp *state )
{
	/* Must be at least one range to cover. */
	if ( state->outList.length() == 0 )
		return false;
	
	/* The first must start at the lower bound. */
	TransList::Iter trans = state->outList.first();
	if ( ctx->keyOps->lt( ctx->keyOps->minKey, trans->lowKey ) )
		return false;

	/* Loop starts at second el. */
	trans.increment();

	/* Loop checks lower against prev upper. */
	for ( ; trans.lte(); trans++ ) {
		/* Lower end of the trans must be one greater than the
		 * previous' high end. */
		Key lowKey = trans->lowKey;
		ctx->keyOps->decrement( lowKey );
		if ( ctx->keyOps->lt( trans->prev->highKey, lowKey ) )
			return false;
	}

	/* Require that the last range extends to the upper bound. */
	trans = state->outList.last();
	if ( ctx->keyOps->lt( trans->highKey, ctx->keyOps->maxKey ) )
		return false;

	return true;
}

/* Remove states that that do not lead to a final states. Works recursivly traversing
 * the graph in reverse (starting from all final states) and marking seen states. Then
 * removes states that did not get marked. */
void FsmAp::removeDeadEndStates()
{
	/* Misfit accounting should be off and there should be no states on the
	 * misfit list. */
	assert( !misfitAccounting && misfitList.length() == 0 );

	/* Mark all states that have paths to the final states. */
	StateAp **st = finStateSet.data;
	int nst = finStateSet.length();
	for ( int i = 0; i < nst; i++, st++ )
		markReachableFromHereReverse( *st );

	/* Start state gets honorary marking. If the machine accepts nothing we
	 * still want the start state to hang around. This must be done after the
	 * recursive call on all the final states so that it does not cause the
	 * start state in transitions to be skipped when the start state is
	 * visited by the traversal. */
	startState->stateBits |= STB_ISMARKED;

	/* Delete all states that are not marked
	 * and unmark the ones that are marked. */
	StateAp *state = stateList.head;
	while ( state != 0 ) {
		StateAp *next = state->next;

		if ( state->stateBits & STB_ISMARKED  )
			state->stateBits &= ~ STB_ISMARKED;
		else {
			detachState( state );
			stateList.detach( state );
			delete state;
		}
		
		state = next;
	}
}

/* Remove states on the misfit list. To work properly misfit accounting should
 * be on when this is called. The detaching of a state will likely cause
 * another misfit to be collected and it can then be removed. */
void FsmAp::removeMisfits()
{
	while ( misfitList.length() > 0 ) {
		/* Get the first state. */
		StateAp *state = misfitList.head;

		/* Detach and delete. */
		detachState( state );

		/* The state was previously on the misfit list and detaching can only
		 * remove in transitions so the state must still be on the misfit
		 * list. */
		misfitList.detach( state );
		delete state;
	}
}

/* Fuse src into dest because they have been deemed equivalent states.
 * Involves moving transitions into src to go into dest and invoking
 * callbacks. Src is deleted detached from the graph and deleted. */
void FsmAp::fuseEquivStates( StateAp *dest, StateAp *src )
{
	/* This would get ugly. */
	assert( dest != src );

	/* Cur is a duplicate. We can merge it with trail. */
	moveInwardTrans( dest, src );

	detachState( src );
	stateList.detach( src );
	delete src;
}

void FsmAp::fuseUnmarkedPairs( MarkIndex &markIndex )
{
	StateAp *p = stateList.head, *nextP, *q;

	/* Definition: The primary state of an equivalence class is the first state
	 * encounterd that belongs to the equivalence class. All equivalence
	 * classes have primary state including equivalence classes with one state
	 * in it. */

	/* For each unmarked pair merge p into q and delete p. q is always the
	 * primary state of it's equivalence class. We wouldn't have landed on it
	 * here if it were not, because it would have been deleted.
	 *
	 * Proof that q is the primaray state of it's equivalence class: Assume q
	 * is not the primary state of it's equivalence class, then it would be
	 * merged into some state that came before it and thus p would be
	 * equivalent to that state. But q is the first state that p is equivalent
	 * to so we have a contradiction. */

	/* Walk all unordered pairs of (p, q) where p != q.
	 * The second depth of the walk stops before reaching p. This
	 * gives us all unordered pairs of states (p, q) where p != q. */
	while ( p != 0 ) {
		nextP = p->next;

		q = stateList.head;
		while ( q != p ) {
			/* If one of p or q is a final state then mark. */
			if ( ! markIndex.isPairMarked( p->alg.stateNum, q->alg.stateNum ) ) {
				fuseEquivStates( q, p );
				break;
			}
			q = q->next;
		}
		p = nextP;
	}
}

void FsmAp::fusePartitions( MinPartition *parts, int numParts )
{
	/* For each partition, fuse state 2, 3, ... into state 1. */
	for ( int p = 0; p < numParts; p++ ) {
		/* Assume that there will always be at least one state. */
		StateAp *first = parts[p].list.head, *toFuse = first->next;

		/* Put the first state back onto the main state list. Don't bother
		 * removing it from the partition list first. */
		stateList.append( first );

		/* Fuse the rest of the state into the first. */
		while ( toFuse != 0 ) {
			/* Save the next. We will trash it before it is needed. */
			StateAp *next = toFuse->next;

			/* Put the state to be fused in to the first back onto the main
			 * list before it is fuse.  the graph. The state needs to be on
			 * the main list for the detach from the graph to work.  Don't
			 * bother removing the state from the partition list first. We
			 * need not maintain it. */
			stateList.append( toFuse );

			/* Now fuse to the first. */
			fuseEquivStates( first, toFuse );

			/* Go to the next that we saved before trashing the next pointer. */
			toFuse = next;
		}

		/* We transfered the states from the partition list into the main list without
		 * removing the states from the partition list first. Clean it up. */
		parts[p].list.abandon();
	}
}

/* Merge neighboring transitions that go to the same state and have the same
 * transitions data. */
void FsmAp::compressTransitions()
{
	for ( StateList::Iter st = stateList; st.lte(); st++ ) {
		if ( st->outList.length() > 1 ) {
			for ( TransList::Iter trans = st->outList, next = trans.next(); next.lte();  ) {
				Key nextLow = next->lowKey;
				ctx->keyOps->decrement( nextLow );

				/* Require there be no conditions in either of the merge
				 * candidates. */
				bool merge = false;
				TransDataAp *td;
				TransDataAp *tn;

				if ( trans->plain() && 
						next->plain() && 
						ctx->keyOps->eq( trans->highKey, nextLow ) )
				{
					td = trans->tdap();
					tn = next->tdap();

					/* Check the condition target and action data. */
					if ( td->toState == tn->toState && CmpActionTable::compare(
							td->actionTable, tn->actionTable ) == 0 )
					{
						merge = true;
					}
				}

				if ( merge ) {
					trans->highKey = next->highKey;
					st->outList.detach( tn );
					detachTrans( tn->fromState, tn->toState, tn );
					delete tn;
					next = trans.next();
				}
				else {
					trans.increment();
					next.increment();
				}
			}
		}
	}
}

bool FsmAp::elimCondBits()
{
	bool modified = false;
	for ( StateList::Iter st = stateList; st.lte(); st++ ) {
		restart:
		for ( TransList::Iter trans = st->outList; trans.lte(); trans++ ) {
			if ( !trans->plain() ) {
				CondSpace *cs = trans->condSpace;

				for ( CondSet::Iter csi = cs->condSet; csi.lte(); csi++ ) {
					long bit = 1 << csi.pos();

					/* Sort into on and off lists. */
					CondList on;
					CondList off;
					TransCondAp *tcap = trans->tcap();
					while ( tcap->condList.length() > 0 ) {
						CondAp *cond = tcap->condList.detachFirst();
						if ( cond->key.getVal() & bit ) {
							cond->key = CondKey( cond->key.getVal() & ~bit );
							on.append( cond );
						}
						else {
							off.append( cond );
						}
					}

					bool merge = false;
					if ( on.length() > 0 && on.length() == off.length() ) {
						/* test if the same */
						int cmpRes = compareCondListBitElim( on, off );
						if ( cmpRes == 0 )
							merge = true;
					}

					if ( merge ) {
						if ( cs->condSet.length() == 1 ) {
							/* clear out the on-list. */
							while ( on.length() > 0 ) {
								CondAp *cond = on.detachFirst();
								detachTrans( st, cond->toState, cond );
							}

							/* turn back into a plain transition. */
							CondAp *cond = off.detachFirst();
							TransAp *n = convertToTransAp( st, cond );
							TransAp *before = trans->prev;
							st->outList.detach( trans );
							st->outList.addAfter( before, n );
							modified = true;
							goto restart;
						}
						else 
						{
							CondSet newSet = cs->condSet;
							newSet.Vector<Action*>::remove( csi.pos(), 1 );
							trans->condSpace = addCondSpace( newSet );

							/* clear out the on-list. */
							while ( on.length() > 0 ) {
								CondAp *cond = on.detachFirst();
								detachTrans( st, cond->toState, cond );
							}
						}
					}

					/* Turn back into a single list. */
					while ( on.length() > 0 || off.length() > 0 ) {
						if ( on.length() == 0 ) {
							while ( off.length() > 0 )
								tcap->condList.append( off.detachFirst() );
						}
						else if ( off.length() == 0 ) {
							while ( on.length() > 0 ) {
								CondAp *cond = on.detachFirst();
								cond->key = CondKey( cond->key.getVal() | bit );
								tcap->condList.append( cond );
							}
						}
						else {
							if ( off.head->key.getVal() < ( on.head->key.getVal() | bit ) ) {
								tcap->condList.append( off.detachFirst() );
							}
							else {
								CondAp *cond = on.detachFirst();
								cond->key = CondKey( cond->key.getVal() | bit );
								tcap->condList.append( cond );
							}
						}
					}

					if ( merge ) {
						modified = true;
						goto restart;
					}
				}
			}
		}
	}
	return modified;
}

/* Perform minimization after an operation according 
 * to the command line args. */
void FsmAp::afterOpMinimize( bool lastInSeq )
{
	/* Switch on the prefered minimization algorithm. */
	if ( ctx->minimizeOpt == MinimizeEveryOp || ( ctx->minimizeOpt == MinimizeMostOps && lastInSeq ) ) {
		/* First clean up the graph. FsmAp operations may leave these
		 * lying around. There should be no dead end states. The subtract
		 * intersection operators are the only places where they may be
		 * created and those operators clean them up. */
		removeUnreachableStates();

		switch ( ctx->minimizeLevel ) {
			#ifdef TO_UPGRADE_CONDS
			case MinimizeApprox:
				minimizeApproximate();
				break;
			#endif
			case MinimizePartition1:
				minimizePartition1();
				break;
			case MinimizePartition2:
				minimizePartition2();
				break;
			#ifdef TO_UPGRADE_CONDS
			case MinimizeStable:
				minimizeStable();
				break;
			#endif
		}
	}
}


/*
 * Copyright 2001, 2003 Adrian Thurston <thurston@colm.net>
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

#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include "avlimel.h"

#define AVLTREE_MEL
#define WALKABLE
#include "avlverify.h"
#undef WALKABLE
#undef AVLTREE_MEL

#include "util.h"

/* Having the action change perion larger than the number of initial entries
 * means that it will take longer to get to all the cases, but all the
 * cases will be more thoroughly tested. The tree will be more likely to
 * empty out completely and fill up with all of the entries. */
#define INITIAL_ENTRIES 64831
#define ACTION_CHANGE_PERIOD 120233
#define VERIFY_PERIOD 1119
#define COPY_PERIOD 1351
#define INCREMENT_VARIATION 10
#define STATS_PERIOD 211
#define OUTBUFSIZE 100

using namespace std;

struct TreeEl;
struct BaseEl1 : public AvliTreeEl< TreeEl > { };
struct BaseEl2 : public AvliTreeEl< TreeEl > { };

struct TreeEl :
		public BaseEl1, 
		public BaseEl2
{
	TreeEl() : inTree1(false), inTree2(false) { }
	TreeEl(const int key) : key(key), inTree1(false), inTree2(false) { }

	const int &getKey() { return key; }

	int key;
	bool inTree1;
	bool inTree2;
};

template class AvliMel< TreeEl, int, BaseEl1 >;
template class AvliMel< TreeEl, int, BaseEl2 >;
template class AvliMelVer< TreeEl, int, BaseEl1 >;
template class AvliMelVer< TreeEl, int, BaseEl2 >;

int increment = 0;
int curIndex = 0;
int action = 1;
int curRound = 0;

/* Replace the current stats line with new stats. For two trees. */
void printStats( int treeSize1, int treeSize2 )
{
	/* Print stats. */
	static char buf[OUTBUFSIZE] = { 0 };
	char tmpBuf[OUTBUFSIZE];

	if ( curRound % STATS_PERIOD == 0 ) {
		memset( buf, '\b', strlen(buf) );
		cout << buf;
		sprintf( tmpBuf, "%i\t%i\t%s\t%s\t%i\t%i\t%i\t", curRound, increment,
				action&0x1 ? "yes" : "no", action&0x2 ? "yes" : "no", 
				curIndex, treeSize1, treeSize2 );
		expandTab( buf, tmpBuf );
		cout << buf;
		cout.flush();
	}
}

/* Find a new curIndex to use. If the increment is 0 then get
 * a random curIndex. Otherwise use the increment. */
void newIndex()
{
	if ( increment == 0 )
		curIndex = random() % INITIAL_ENTRIES;
	else
		curIndex = (curIndex + increment) % INITIAL_ENTRIES;
}

/* Print the header to the stats. For two trees*/
void printHeader()
{
	char buf[OUTBUFSIZE];
	expandTab( buf, "round\tinc\tins\trem\tindex\tels1\tels2" );
	cout << buf << endl;
}

int main( int argc, char **argv )
{
	processArgs( argc, argv );
	srandom( time(0) );

	/* Make the tree and element. */
	AvliMelVer< TreeEl, int, BaseEl1 > tree1;
	AvliMelVer< TreeEl, int, BaseEl2 > tree2;
	TreeEl *allElements = new TreeEl[INITIAL_ENTRIES];
	for ( int element = 0; element < INITIAL_ENTRIES; element++ )
		allElements[element].key = element;
	
	printHeader();

	for ( curRound = 0; true; curRound++ ) {
		/* Do we change our action? */
		if ( curRound % ACTION_CHANGE_PERIOD == 0 ) {
			increment = random() % 2;
			if ( increment > 0 )
				increment = random() % INCREMENT_VARIATION;

			action = (random()%3) + 1;
		}

		/* Dump stats. */
		printStats( tree1.treeSize, tree2.treeSize );

		/* Insert one to tree1? */
		if ( action&0x1 ) {
			newIndex();
			/* Insert from the pool of existing element. */
			if ( ! allElements[curIndex].inTree1 ) {
				tree1.insert( allElements+curIndex );
				allElements[curIndex].inTree1 = true;
			}
		}

		/* Insert one to tree2? */
		if ( action&0x1 ) {
			newIndex();
			/* Insert from the pool of existing element. */
			if ( ! allElements[curIndex].inTree2 ) {
				tree2.insert( allElements+curIndex );
				allElements[curIndex].inTree2 = true;
			}
		}

		/* Delete one from tree1? */
		if ( action&0x2 ) {
			newIndex();
			/* Delete from the pool of existing entries. */
			if ( allElements[curIndex].inTree1 ) {
				tree1.detach( allElements+curIndex );
				allElements[curIndex].inTree1 = false;
			}
		}

		/* Delete one from tree2? */
		if ( action&0x2 ) {
			newIndex();
			/* Delete from the pool of existing entries. */
			if ( allElements[curIndex].inTree2 ) {
				tree2.detach( allElements+curIndex );
				allElements[curIndex].inTree2 = false;
			}
		}

		/* Verify? */
		if ( curRound % VERIFY_PERIOD == 0 ) {
			tree1.verifyIntegrity();
			tree2.verifyIntegrity();
		}

		/* Test the copy constructor? */
		if ( curRound % COPY_PERIOD == 0 ) {
			AvliMelVer< TreeEl, int, BaseEl1 > copy1( tree1 );
			AvliMelVer< TreeEl, int, BaseEl2 > copy2( tree2 );
			copy1.verifyIntegrity();
			copy2.verifyIntegrity();
			copy1.empty();
			copy2.empty();
		}

	}	
	return 0;
}

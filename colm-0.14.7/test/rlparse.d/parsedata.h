/*
 *  Copyright 2001-2008 Adrian Thurston <thurston@complang.org>
 */

/*  This file is part of Ragel.
 *
 *  Ragel is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 * 
 *  Ragel is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with Ragel; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 */

#ifndef _PARSEDATA_H
#define _PARSEDATA_H

#include <iostream>
#include <limits.h>
#include <sstream>
#include <vector>
#include <set>

#include "avlmap.h"
#include "bstmap.h"
#include "vector.h"
#include "dlist.h"
#include "fsmgraph.h"
#include "compare.h"
#include "vector.h"
#include "common.h"
#include "parsetree.h"
#include "action.h"


/* Forwards. */
using std::ostream;

struct VarDef;
struct Join;
struct Expression;
struct Term;
struct FactorWithAug;
struct FactorWithLabel;
struct FactorWithRep;
struct FactorWithNeg;
struct Factor;
struct Literal;
struct Range;
struct RegExpr;
struct ReItem;
struct ReOrBlock;
struct ReOrItem;
struct LongestMatch;
struct CodeGenData;
struct InputData;
struct InputItem;

typedef DList<LongestMatch> LmList;

/* This is used for tracking the include files/machine pairs. */
struct IncludeHistoryItem
{
	IncludeHistoryItem( const char *fileName, const char *sectionName )
		: fileName(fileName), sectionName(sectionName) {}

	std::string fileName;
	std::string sectionName;
};

typedef std::vector<IncludeHistoryItem> IncludeHistory;

/* Graph dictionary. */
struct GraphDictEl 
:
	public AvlTreeEl<GraphDictEl>,
	public DListEl<GraphDictEl>
{
	GraphDictEl( std::string k ) 
		: key(k), value(0), isInstance(false) { }
	GraphDictEl( std::string k, VarDef *value ) 
		: key(k), value(value), isInstance(false) { }
	
	~GraphDictEl()
	{
		delete value;
	}

	std::string getKey() { return key; }

	std::string key;
	VarDef *value;
	bool isInstance;

	/* Location info of graph definition. Points to variable name of assignment. */
	InputLoc loc;
};

typedef AvlTree<GraphDictEl, std::string, CmpString> GraphDict;
typedef DList<GraphDictEl> GraphList;

/* Priority name dictionary. */
typedef AvlMapEl<std::string, int> PriorDictEl;
typedef AvlMap<std::string, int, CmpString> PriorDict;

/* Local error name dictionary. */
typedef AvlMapEl<std::string, int> LocalErrDictEl;
typedef AvlMap<std::string, int, CmpString> LocalErrDict;

struct NameMapVal
{
	Vector<NameInst*> vals;
};

/* Tree of instantiated names. */
typedef AvlMapEl<std::string, NameMapVal*> NameMapEl;
typedef AvlMap<std::string, NameMapVal*, CmpString> NameMap;
typedef Vector<NameInst*> NameVect;
typedef BstSet<NameInst*> NameSet;

/* Node in the tree of instantiated names. */
struct NameInst
{
	NameInst( const InputLoc &loc, NameInst *parent, std::string name, int id, bool isLabel ) : 
		loc(loc), parent(parent), name(name), id(id), isLabel(isLabel),
		isLongestMatch(false), numRefs(0), numUses(0), start(0), final(0) {}

	~NameInst();

	InputLoc loc;

	/* Keep parent pointers in the name tree to retrieve 
	 * fully qulified names. */
	NameInst *parent;

	std::string name;
	int id;
	bool isLabel;
	bool isLongestMatch;

	int numRefs;
	int numUses;

	/* Names underneath us, excludes anonymous names. */
	NameMap children;

	/* All names underneath us in order of appearance. */
	NameVect childVect;

	/* Join scopes need an implicit "final" target. */
	NameInst *start, *final;

	/* During a fsm generation walk, lists the names that are referenced by
	 * epsilon operations in the current scope. After the link is made by the
	 * epsilon reference and the join operation is complete, the label can
	 * have its refcount decremented. Once there are no more references the
	 * entry point can be removed from the fsm returned. */
	NameVect referencedNames;

	/* Pointers for the name search queue. */
	NameInst *prev, *next;

	/* Check if this name inst or any name inst below is referenced. */
	bool anyRefsRec();
};

typedef DList<NameInst> NameInstList;

/* Stack frame used in walking the name tree. */
struct NameFrame 
{
	NameInst *prevNameInst;
	int prevNameChild;
	NameInst *prevLocalScope;
};

struct LengthDef
{
	LengthDef( char *name )
		: name(name) {}

	char *name;
	LengthDef *prev, *next;
};

typedef DList<LengthDef> LengthDefList;

extern const int ORD_PUSH;
extern const int ORD_RESTORE;
extern const int ORD_COND;
extern const int ORD_TEST;

/* Class to collect information about the machine during the 
 * parse of input. */
struct ParseData
{
	/* Create a new parse data object. This is done at the beginning of every
	 * fsm specification. */
	ParseData( InputData *id, std::string sectionName,
			int machineId, const InputLoc &sectionLoc, const HostLang *hostLang,
			MinimizeLevel minimizeLevel, MinimizeOpt minimizeOpt );
	~ParseData();

	/*
	 * Setting up the graph dict.
	 */

	/* Initialize a graph dict with the basic fsms. */
	void initGraphDict();
	void createBuiltin( const char *name, BuiltinMachine builtin );

	/* Make a name id in the current name instantiation scope if it is not
	 * already there. */
	NameInst *addNameInst( const InputLoc &loc, std::string data, bool isLabel );
	void makeRootNames();
	void makeNameTree( GraphDictEl *gdNode );
	void makeExportsNameTree();
	void fillNameIndex( NameInst *from );

	/* Increments the usage count on entry names. Names that are no longer
	 * needed will have their entry points unset. */
	void unsetObsoleteEntries( FsmAp *graph );

	/* Resove name references in action code and epsilon transitions. */
	NameSet resolvePart( NameInst *refFrom, const std::string &data, bool recLabelsOnly );
	void resolveFrom( NameSet &result, NameInst *refFrom, 
			NameRef *nameRef, int namePos );
	NameInst *resolveStateRef( NameRef *nameRef, InputLoc &loc, Action *action );
	void resolveNameRefs( InlineList *inlineList, Action *action );
	void resolveActionNameRefs();

	/* Set the alphabet type. If type types are not valid returns false. */
	bool setAlphType( const InputLoc &loc, const HostLang *hostLang,
			const char *s1 );
	bool setAlphType( const InputLoc &loc, const HostLang *hostLang,
			const char *s1, const char *s2 );

	/* Override one of the variables ragel uses. */
	bool setVariable( const char *var, InlineList *inlineList );

	/* Dumping the name instantiation tree. */
	void printNameInst( std::ostream &out, NameInst *nameInst, int level );
	void printNameTree( std::ostream &out );

	void analysisResult( long code, long id, const char *scode );

	void reportBreadthResults( BreadthResult *breadth );
	BreadthResult *checkBreadth( FsmAp *fsm );
	void reportAnalysisResult( FsmRes &res );

	/* Make the graph from a graph dict node. Does minimization. */
	FsmRes makeInstance( GraphDictEl *gdNode );
	FsmRes makeSpecific( GraphDictEl *gdNode );
	FsmRes makeAll();

	void makeExports();

	FsmRes prepareMachineGen( GraphDictEl *graphDictEl, const HostLang *hostLang );
	void generateXML( ostream &out );
	void generateReduced( const char *inputFileName, CodeStyle codeStyle,
			std::ostream &out, const HostLang *hostLang );

	std::string sectionName;
	FsmAp *sectionGraph;

	void initKeyOps( const HostLang *hostLang );

	void errorStateLabels( const NameSet &resolved );

	/*
	 * Data collected during the parse.
	 */

	/* Dictionary of graphs. Both instances and non-instances go here. */
	GraphDict graphDict;

	/* The list of instances. */
	GraphList instanceList;

	/* Dictionary of actions. Lets actions be defined and then referenced. */
	ActionDict actionDict;

	/* Dictionary of named priorities. */
	PriorDict priorDict;

	/* Dictionary of named local errors. */
	LocalErrDict localErrDict;

	/* Various next identifiers. */
	int nextLocalErrKey, nextNameId;
	
	/* The default priority number key for a machine. This is active during
	 * the parse of the rhs of a machine assignment. */
	int curDefPriorKey;

	int curDefLocalErrKey;

	/* Alphabet type. */
	HostType *alphType;
	HostType *userAlphType;
	bool alphTypeSet;
	InputLoc alphTypeLoc;

	/* The alphabet range. */
	char *lowerNum, *upperNum;
	Key lowKey, highKey;
	InputLoc rangeLowLoc, rangeHighLoc;

	InputData *id;

	/* The name of the file the fsm is from, and the spec name. */
	int machineId;
	InputLoc sectionLoc;

	/* Root of the name tree. One root is for the instantiated machines. The
	 * other root is for exported definitions. */
	NameInst *rootName;
	NameInst *exportsRootName;
	
	/* Name tree walking. */
	NameInst *curNameInst;
	int curNameChild;

	/* The place where resolved epsilon transitions go. These cannot go into
	 * the parse tree because a single epsilon op can resolve more than once
	 * to different nameInsts if the machine it's in is used more than once. */
	NameVect epsilonResolvedLinks;
	int nextEpsilonResolvedLink;

	/* Root of the name tree used for doing local name searches. */
	NameInst *localNameScope;

	void setLmInRetLoc( InlineList *inlineList );
	void initLongestMatchData();
	void setLongestMatchData( FsmAp *graph );
	void initNameWalk();
	void initExportsNameWalk();
	NameInst *nextNameScope() { return curNameInst->childVect[curNameChild]; }
	NameFrame enterNameScope( bool isLocal, int numScopes );
	void popNameScope( const NameFrame &frame );
	void resetNameScope( const NameFrame &frame );

	void nfaTermCheckKleeneZero();
	void nfaTermCheckMinZero();
	void nfaTermCheckPlusZero();
	void nfaTermCheckRepZero();
	void nfaTermCheckZeroReps();

	void clear();

	/* Counter for assigning ids to longest match items. */
	int nextLongestMatchId;

	int nextRepId;

	/* List of all longest match parse tree items. */
	LmList lmList;

	Action *newLmCommonAction( const char *name, InlineList *inlineList );

	Action *initTokStart;
	int initTokStartOrd;

	Action *setTokStart;
	int setTokStartOrd;

	Action *initActId;
	int initActIdOrd;

	Action *setTokEnd;
	int setTokEndOrd;

	LengthDefList lengthDefList;

	CodeGenData *cgd;

	struct Cut
	{
		Cut( std::string name, int entryId )
			: name(name), entryId(entryId) {}

		std::string name;
		int entryId;
	};

	/* Track the cuts we set in the fsm graph. We perform cost analysis on the
	 * built fsm graph for each of these entry points. */
	Vector<Cut> cuts;

	ParseData *prev, *next;

	FsmCtx *fsmCtx;

	/* Make a list of places to look for an included file. */
	bool duplicateInclude( const char *inclFileName, const char *inclSectionName );

	IncludeHistory includeHistory;

	std::set<std::string> actionParams;

	void dump();
};

Key makeFsmKeyHex( char *str, const InputLoc &loc, ParseData *pd );
Key makeFsmKeyDec( char *str, const InputLoc &loc, ParseData *pd );
Key makeFsmKeyNum( char *str, const InputLoc &loc, ParseData *pd );
Key makeFsmKeyChar( char c, ParseData *pd );
void makeFsmKeyArray( Key *result, char *data, int len, ParseData *pd );
void makeFsmUniqueKeyArray( KeySet &result, const char *data, int len, 
		bool caseInsensitive, ParseData *pd );
FsmAp *makeBuiltin( BuiltinMachine builtin, ParseData *pd );
FsmAp *dotFsm( ParseData *pd );
FsmAp *dotStarFsm( ParseData *pd );

Key *prepareHexString( ParseData *pd, const InputLoc &loc,
		const char *data, long length, long &resLen );
char *prepareLitString( InputData *id, const InputLoc &loc, const char *data, long length, 
		long &resLen, bool &caseInsensitive );
const char *checkLitOptions( InputData *id, const InputLoc &loc,
		const char *data, int length, bool &caseInsensitive );

#endif

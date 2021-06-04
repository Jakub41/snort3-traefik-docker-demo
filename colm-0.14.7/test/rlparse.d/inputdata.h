/*
 *  Copyright 2008 Adrian Thurston <thurston@complang.org>
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

#ifndef _INPUT_DATA
#define _INPUT_DATA

#include <iostream>
#include <sstream>
#include <vector>

#include "gendata.h"

using std::ostream;
using std::string;

struct ParseData;
struct Parser6;
struct CondSpace;
struct CondAp;
struct ActionTable;
struct Section;

void translatedHostData( ostream &out, const string &data );

struct InputItem
{
	InputItem()
	:
		section(0),
		pd(0),
		parser(0),
		processed(false)
	{}

	enum Type {
		HostData,
		EndSection,
		Write,
	};

	Type type;
	std::ostringstream data;
	std::string name;
	Section *section;
	ParseData *pd;
	Parser6 *parser;
	std::vector<std::string> writeArgs;

	InputLoc loc;
	bool processed;

	InputItem *prev, *next;
};

struct IncItem
{
	IncItem()
	:
		section(0)
	{}

	Section *section;
	InputLoc loc;
	long start, end;
	size_t length;
	IncItem *prev, *next;
};


typedef AvlMap<std::string, ParseData*, CmpString> ParseDataDict;
typedef AvlMapEl<std::string, ParseData*> ParseDataDictEl;
typedef DList<ParseData> ParseDataList;

/* This exists for ragel-6 parsing. */
typedef AvlMap<const char*, Parser6*, CmpStr> ParserDict;
typedef AvlMapEl<const char*, Parser6*> ParserDictEl;
typedef DList<Parser6> ParserList;

typedef DList<InputItem> InputItemList;
typedef DList<IncItem> IncItemList;
typedef Vector<const char *> ArgsVector;

struct Section
{
	Section( std::string sectionName )
	:
		sectionName(sectionName),
		lastReference(0)
	{}

	std::string sectionName;

	/* Pointer to the last input item to reference this parse data struct. Once
	 * we pass over this item we are free to clear away the parse tree. */
	InputItem *lastReference;

	Section *prev, *next;
};

typedef AvlMap<std::string, Section*, CmpString> SectionDict;
typedef AvlMapEl<std::string, Section*> SectionDictEl;
typedef DList<Section> SectionList;

struct FnMachine
{
	FnMachine( const string &fileName, const string &machine )
		: fileName( fileName ), machine( machine ) {}

	string fileName;
	string machine;
};

struct CmpFnMachine
{
	static inline int compare( const FnMachine &k1, const FnMachine &k2 )
	{
		int r = strcmp( k1.fileName.c_str(), k2.fileName.c_str() );
		if ( r != 0 )
			return r;
		else {
			r = strcmp( k1.machine.c_str(), k2.machine.c_str() );
			if ( r != 0 )
				return r;
		}
		return 0;
	}
};

struct IncludeRec
	: public AvlTreeEl<IncludeRec>
{
	IncludeRec( const string &fileName, const string &machine )
		: key( fileName, machine ), data(0) {}
	
	~IncludeRec()
	{
		if ( data != 0 )
			delete[] data;
	}

	FnMachine key;

	const FnMachine &getKey()
		{ return key; }

	std::string foundFileName;
	
	char *data;
	int len;

};

typedef AvlTree<IncludeRec, FnMachine, CmpFnMachine> IncludeDict;

struct InputData
:
	public FsmGbl
{
	InputData()
	: 
		inputFileName(0),
		outputFileName(0),
		commFileName(0),
		nextMachineId(0),
		inStream(0),
		outStream(0),
		outFilter(0),
		curItem(0),
		lastFlush(0),
		hostLang(&hostLangC),
		codeStyle(GenBinaryLoop),
		dotGenPd(0),
		machineSpec(0),
		machineName(0),
		generateDot(false),
		noLineDirectives(false),
		maxTransitions(LONG_MAX),
		numSplitPartitions(0),
		rubyImpl(MRI),
		rlhcShowCmd(false),
		noIntermediate(false),
		frontendSpecified(false),
		backendSpecified(false),
		featureSpecified(false),
		saveTemps(false),
		condsCheckDepth(-1),
		transSpanDepth(6),
		stateLimit(0),
		checkBreadth(0),
		varBackend(false),
		histogramFn(0),
		histogram(0),
		input(0),
		forceLibRagel(false)
	{}

	~InputData();

	void usage();
	void version();
	void showHostLangNames();
	void showHostLangArgs();
	void showFrontends();
	void showBackends();
	void showStyles();

	std::string dirName;

	/* The name of the root section, this does not change during an include. */
	const char *inputFileName;
	const char *outputFileName;
	const char *commFileName;

	string comm;

	int nextMachineId;

	std::string origOutputFileName;
	std::string genOutputFileName;

	/* Io globals. */
	std::istream *inStream;
	std::ostream *outStream;
	output_filter *outFilter;

	ParseDataDict parseDataDict;
	ParseDataList parseDataList;
	InputItemList inputItems;
	InputItem *curItem;
	InputItem *lastFlush;

	const HostLang *hostLang;

	/* Ragel-6 frontend. */
	ParserDict parserDict;
	ParserList parserList;

	SectionDict sectionDict;
	SectionList sectionList;

	ArgsVector includePaths;

	bool isBreadthLabel( const string &label );
	ArgsVector breadthLabels;

	/* Target language and output style. */
	CodeStyle codeStyle;

	ParseData *dotGenPd;

	const char *machineSpec;
	const char *machineName;

	bool generateDot;

	bool noLineDirectives;

	long maxTransitions;
	int numSplitPartitions;

	/* Target ruby impl */
	RubyImplEnum rubyImpl;

	bool rlhcShowCmd;
	bool noIntermediate;

	bool frontendSpecified;
	RagelFrontend frontend;

	bool backendSpecified;

	bool featureSpecified;

	bool saveTemps;
	long condsCheckDepth;
	long transSpanDepth;
	long stateLimit;
	bool checkBreadth;

	bool varBackend;

	IncludeDict includeDict;

	const char *histogramFn;
	double *histogram;

	const char *input;

	Vector<const char**> streamFileNames;

	void verifyWriteHasData( InputItem *ii );
	void verifyWritesHaveData();

	void makeTranslateOutputFileName();
	void flushRemaining();
	void makeFirstInputItem();
	void writeOutput();
	void makeDefaultFileName();
	void createOutputStream();
	void openOutput();
	void closeOutput();
	void generateReduced();
	void prepareSingleMachine();
	void prepareAllMachines();

	void cdDefaultFileName( const char *inputFile );
	void goDefaultFileName( const char *inputFile );
	void javaDefaultFileName( const char *inputFile );
	void rubyDefaultFileName( const char *inputFile );
	void csharpDefaultFileName( const char *inputFile );
	void ocamlDefaultFileName( const char *inputFile );
	void crackDefaultFileName( const char *inputFile );
	void asmDefaultFileName( const char *inputFile );
	void rustDefaultFileName( const char *inputFile );
	void juliaDefaultFileName( const char *inputFile );
	void jsDefaultFileName( const char *inputFile );

	void writeOutput( InputItem *ii );
	void writeLanguage( std::ostream &out );

	bool checkLastRef( InputItem *ii );

	void parseKelbt();
	void processDot();
	void processCode();
	void processCodeEarly();

	void writeDot( std::ostream &out );

	void loadHistogram();
	void defaultHistogram();

	void parseArgs( int argc, const char **argv );
	void checkArgs();
	void terminateParser( Parser6 *parser );
	void terminateAllParsers();

	void runRlhc();
	void processKelbt();
	void processColm();
	bool processReduce();
	bool process();
	bool parseReduce();

	char *readInput( const char *inputFileName );

	bool forceLibRagel;

	const char **makeIncludePathChecks( const char *curFileName, const char *fileName );
	std::ifstream *tryOpenInclude( const char **pathChecks, long &found );
};


#endif

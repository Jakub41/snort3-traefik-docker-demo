/*
 * Copyright 2002 Adrian Thurston <thurston@colm.net>
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

#include <iostream>
#include "dlistval.h"
using namespace std;

template class DListVal<int>;
typedef DListVal<int> List;

void testDoubleList()
{
	List list, list2;
	list.append( 1 );
	list.append( 2 );
	list.append( 3 );
	list.append( 4 );

	List::Iter it = list;
	while ( !it.end() && it->value != 3 )
		it++;

	list2 = list;
	cout << it->value << endl;
}

void testDLIter()
{
	List list;

	cout << "Iterator Default Constructor" << endl;

	/* Default constructed iterator. */
	List::Iter defIt;
	cout << defIt.lte() << " " << defIt.end() << " " << defIt.gtb() << " " << 
			defIt.beg() << " " << defIt.first() << " " << defIt.last() << endl;

	cout << "Zero Items" << endl;

	/* Iterator constructed from empty list. */
	List::Iter i1(list);
	cout << i1.lte() << " " << i1.end() << " " << i1.gtb() << " " << 
			i1.beg() << " " << i1.first() << " " << i1.last() << endl;
	List::Iter i2(list.first());
	cout << i2.lte() << " " << i2.end() << " " << i2.gtb() << " " << 
			i2.beg() << " " << i2.first() << " " << i2.last() << endl;
	List::Iter i3(list.last());
	cout << i3.lte() << " " << i3.end() << " " << i3.gtb() << " " << 
			i3.beg() << " " << i3.first() << " " << i3.last() << endl;
	
	/* Iterator assigned from an empty list. */
	i1 = list;
	cout << i1.lte() << " " << i1.end() << " " << i1.gtb() << " " << 
			i1.beg() << " " << i1.first() << " " << i1.last() << endl;
	i2 = list.first();
	cout << i2.lte() << " " << i2.end() << " " << i2.gtb() << " " << 
			i2.beg() << " " << i2.first() << " " << i2.last() << endl;
	i3 = list.last();
	cout << i3.lte() << " " << i3.end() << " " << i3.gtb() << " " << 
			i3.beg() << " " << i3.first() << " " << i3.last() << endl;

	cout << "One Item" << endl;
	list.append( 1 );

	/* Iterator constructed from an a list with one item. */
	List::Iter i4(list);
	cout << i4.lte() << " " << i4.end() << " " << i4.gtb() << " " << 
			i4.beg() << " " << i4.first() << " " << i4.last() << endl;
	List::Iter i5(list.first());
	cout << i5.lte() << " " << i5.end() << " " << i5.gtb() << " " << 
			i5.beg() << " " << i5.first() << " " << i5.last() << endl;
	List::Iter i6(list.last());
	cout << i6.lte() << " " << i6.end() << " " << i6.gtb() << " " << 
			i6.beg() << " " << i6.first() << " " << i6.last() << endl;

	/* Iterator assigned from an a list with one item. */
	i4 = list;
	cout << i4.lte() << " " << i4.end() << " " << i4.gtb() << " " << 
			i4.beg() << " " << i4.first() << " " << i4.last() << endl;
	i5 = list.first();
	cout << i5.lte() << " " << i5.end() << " " << i5.gtb() << " " << 
			i5.beg() << " " << i5.first() << " " << i5.last() << endl;
	i6 = list.last();
	cout << i6.lte() << " " << i6.end() << " " << i6.gtb() << " " << 
			i6.beg() << " " << i6.first() << " " << i6.last() << endl;

	cout << "Two Items" << endl;
	list.append( 2 );

	/* Iterator constructed from an a list with two items. */
	List::Iter i7(list);
	cout << i7.lte() << " " << i7.end() << " " << i7.gtb() << " " << 
			i7.beg() << " " << i7.first() << " " << i7.last() << endl;
	List::Iter i8(list.first());
	cout << i8.lte() << " " << i8.end() << " " << i8.gtb() << " " << 
			i8.beg() << " " << i8.first() << " " << i8.last() << endl;
	List::Iter i9(list.last());
	cout << i9.lte() << " " << i9.end() << " " << i9.gtb() << " " << 
			i9.beg() << " " << i9.first() << " " << i9.last() << endl;

	/* Iterator assigned from an a list with two items. */
	i7 = list;
	cout << i7.lte() << " " << i7.end() << " " << i7.gtb() << " " << 
			i7.beg() << " " << i7.first() << " " << i7.last() << endl;
	i8 = list.first();
	cout << i8.lte() << " " << i8.end() << " " << i8.gtb() << " " << 
			i8.beg() << " " << i8.first() << " " << i8.last() << endl;
	i9 = list.last();
	cout << i9.lte() << " " << i9.end() << " " << i9.gtb() << " " << 
			i9.beg() << " " << i9.first() << " " << i9.last() << endl;

	list.empty();
	list.append( 1 );
	list.append( 2 );
	list.append( 3 );
	list.append( 4 );

	cout << "test1" << endl;
	List::Iter it1 = list;
	for ( ; it1.lte(); it1++ )
		cout << it1->value << endl;

	cout << "test2" << endl;
	List::Iter it2 = list.first();
	for ( ; it2.lte(); it2++ )
		cout << it2->value << endl;

	cout << "test3" << endl;
	List::Iter it3 = list.last();
	for ( ; it3.gtb(); it3-- )
		cout << it3->value << endl;

	cout << "test4" << endl;
	it1 = list;
	for ( ; !it1.end(); it1++ )
		cout << it1->value << endl;

	cout << "test5" << endl;
	it2 = list.first();
	for ( ; !it2.end(); it2++ )
		cout << it2->value << endl;

	cout << "test6" << endl;
	it3 = list.last();
	for ( ; !it3.beg(); it3-- )
		cout << it3->value << endl;
}

int main()
{
	testDoubleList();
	testDLIter();
	return 0;
}


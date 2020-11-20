grammar TrafficClass;

WHITESPACE: [ \r\n\t]+ -> skip;
DIGITS: '0' | [1-9] [0-9]*;
HEX_DIGITS: ('a' .. 'f' | 'A' .. 'F' | [0-9])+;
NET: DIGITS '.' DIGITS '.' DIGITS '.' DIGITS '/' DIGITS;

ANY: 'ANY' | 'any';
ALL: 'ALL' | 'all';
NOT: 'NOT' | 'not';
BOOL: 'BOOL' | 'bool';
SRC: 'SRC' | 'src';
DST: 'DST' | 'dst';
DSCP: 'DSCP' | 'dscp';
TOS: 'TOS' | 'tos';
PROTOCOL: 'PROTOCOL' | 'protocol';
SRCPORT: 'SRCPORT' | 'srcport';
DSTPORT: 'DSTPORT' | 'dstport';

STRING: [a-zA-Z]+;

matchSrc: SRC '=' NET;
matchDst: DST '=' NET;
matchDSCP: DSCP '=0x' (HEX_DIGITS | DIGITS);
matchTOS: TOS '=0x' (HEX_DIGITS | DIGITS);
matchProtocol: PROTOCOL '=' STRING;

matchSrcPort: SRCPORT '=' DIGITS;
matchSrcPortRange: SRCPORT '=' DIGITS '-' DIGITS;
matchDstPort: DSTPORT '=' DIGITS;
matchDstPortRange: DSTPORT '=' DIGITS '-' DIGITS;

condCls: 'cls=' DIGITS;
condAny: ANY '(' cond (',' cond)* ')';
condAll: ALL '(' cond (',' cond)* ')';
condNot: NOT '(' cond ')';
condBool: BOOL '=' ('true' | 'false');

condIPv4: matchSrc | matchDst | matchDSCP | matchTOS | matchProtocol;
condPort: matchSrcPort | matchSrcPortRange | matchDstPort | matchDstPortRange;
cond: condAll | condAny | condNot | condIPv4 | condPort | condCls | condBool;

trafficClass: cond EOF;

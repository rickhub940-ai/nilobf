import {OP} from './opcodes.mjs';

export const isResultProducer = row => row &&
 (row[0] === OP.BINARY && row[4] >= 1 && row[4] <= 13 ||
  row[0] === OP.UNARY && row[3] >= 1 && row[3] <= 3);

// Only owned register operands. Heap operations/calls cannot occur inside a
// proven corridor; GETTABLE is admitted as its terminal consumer only.
export function resultConsumerSlots(row, semanticReceipts=false) {
 if (isResultProducer(row)) return row[0] === OP.BINARY ? [2,3] : [2];
 if (!semanticReceipts || !row) return [];
 if ([OP.JF,OP.JT,OP.JNIL].includes(row[0])) return [1];
 if (row[0] === OP.GETTABLE) return [3];
 return [];
}
export function resultConsumerKind(row) {
 if ([OP.JF,OP.JT,OP.JNIL].includes(row[0])) return 'branch';
 if (row[0] === OP.GETTABLE) return 'index';
 return 'arithmetic';
}

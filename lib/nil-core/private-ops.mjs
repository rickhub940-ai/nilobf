// Compiler-owned value operations; these IDs never appear as delivered slots.
export const PRIVATE_GET=259, PRIVATE_DENY=260, PRIVATE_INIT=261, PRIVATE_CAP=262, PRIVATE_SELECT=263, PRIVATE_OPEN=264, PRIVATE_SPAN=265, PRIVATE_ARITHMETIC=266;
export const PRIVATE_DESCRIPTOR=267;
export const PRIVATE_CAPTURE=268,PRIVATE_RECEIVE=269;
export const privateRoles=new Map([[PRIVATE_GET,['r','i']],[PRIVATE_DENY,['r']],[PRIVATE_INIT,['r']],[PRIVATE_CAP,['r','i']],[PRIVATE_SELECT,['r','r','r','j']],[PRIVATE_OPEN,['r','r','r']],[PRIVATE_SPAN,['r','r']],[PRIVATE_ARITHMETIC,['r','b','b','j']]]);
privateRoles.set(PRIVATE_DESCRIPTOR,['l','k']);
privateRoles.set(PRIVATE_CAPTURE,['r','r','r','j']);
privateRoles.set(PRIVATE_RECEIVE,['r']);

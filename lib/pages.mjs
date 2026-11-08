import { randomBytes } from 'node:crypto';
import { buildNilWrapper, leadingMarkerComment } from './__nil.mjs';
import { opaqueSourceBytes } from './nil-core/opaque.mjs';
import { opaqueWrapperProgram } from './nil-core/wrapper-program.mjs';
import { jointMaterializer, attachMaterializer } from './nil-core/joint-materializer.mjs';
import { dataProgram, serializeData, dataSchema } from './nil-core/data-vm.mjs';
import { activateResultLinks } from './nil-core/result-links.mjs';
import { analyzeEmulationSurface } from './nil-core/emulation-surface.mjs';

const ALLOWED = new Set(['markerComment', 'maxSteps', 'contextCount', 'packetLayout', 'recordCacheLimit', 'diagnostics', 'onDiagnostics', 'onStructure', 'onEffectGraph', 'activatedConstants', 'consumerHandlers', 'sharedHandlers', 'wordFeedback', 'denseMetadata', 'callableEntry', 'identityWitness', 'nonlinearFeedback', 'compressionMode', 'entropyCoding', 'compactTransport', 'nativeCipher', 'cfgResultLinks', 'boundPages', 'leanRuntime', 'semanticReceipts', 'keyedDirectory', 'narrowRecords', 'entropyStreams', 'compactPrototypeMetadata', 'compactRegisters', 'sealedRecords', 'bitPackedRecords', 'bitPackedConstants', 'bufferLanes']);
const FIXED = Object.freeze({
  nativeMode: 'joint', inlinePages: true, pageGates: true,
  objectProtocol: true, effectGraph: true, fetchTransitions: true,
  valueReceipts: true, resultLinks: true, packedDescriptors: true,
  streamMasks: true, nativeCompression: true, compactRecords: true,
  batchSpans: true, fastCipher: true, scopeAliases: true,
  fastTransport: true, sectionTransport: true, requireBuffer: true,
});

/** Candidate only: no user source parsing, named entry lookup or packet shortcut. */
export function wrapSourceWithPages(source, options = {}) {
  for (const name of Object.keys(options)) {
    if (!ALLOWED.has(name)) throw new TypeError('Unsupported pages option: ' + name);
  }
  for (const name of ['activatedConstants', 'consumerHandlers', 'sharedHandlers', 'wordFeedback', 'denseMetadata', 'callableEntry', 'identityWitness', 'nonlinearFeedback', 'entropyCoding', 'compactTransport', 'nativeCipher', 'cfgResultLinks', 'boundPages', 'leanRuntime', 'semanticReceipts', 'keyedDirectory', 'narrowRecords', 'entropyStreams', 'compactPrototypeMetadata', 'compactRegisters', 'sealedRecords', 'bitPackedRecords', 'bitPackedConstants', 'bufferLanes']) {
    if (options[name] !== undefined && typeof options[name] !== 'boolean') throw new TypeError(name + ' must be boolean');
  }
  for (const name of ['onStructure', 'onDiagnostics', 'onEffectGraph']) {
    if (options[name] !== undefined && typeof options[name] !== 'function') throw new TypeError(name + ' must be a function');
  }
  const bytes = opaqueSourceBytes(source);
  const keyedDirectory=options.keyedDirectory??!options.denseMetadata;
  options={...options,keyedDirectory,narrowRecords:options.narrowRecords??keyedDirectory,compactPrototypeMetadata:options.compactPrototypeMetadata??keyedDirectory,compactRegisters:options.compactRegisters??true,sealedRecords:options.sealedRecords??true};
  options.bitPackedRecords=options.bitPackedRecords??options.narrowRecords;
  options.activatedConstants=options.activatedConstants??options.bitPackedRecords;
  options.bitPackedConstants=options.bitPackedConstants??(options.activatedConstants&&options.bitPackedRecords);
  options.bufferLanes=options.bufferLanes??(options.sealedRecords&&options.bitPackedRecords);
  if(options.bufferLanes&&(!options.sealedRecords||!options.keyedDirectory||!options.bitPackedRecords))throw new TypeError('Buffer lanes require sealed keyed bit records');
  if(options.bitPackedRecords&&!options.narrowRecords)throw new TypeError('Bit records require narrow records');
  if(options.bitPackedConstants&&!options.activatedConstants)throw new TypeError('Bit constants require activated constants');
  if(options.compactPrototypeMetadata&&!keyedDirectory)throw new TypeError('Compact prototypes require keyed directory');
  if(options.boundPages&&(!options.nativeCipher||!options.wordFeedback||!options.nonlinearFeedback))throw new TypeError('Bound pages require nativeCipher, wordFeedback and nonlinearFeedback');
  if(options.leanRuntime&&!options.nativeCipher)throw new TypeError('Lean runtime requires nativeCipher');
  if(options.nativeCipher&&!options.wordFeedback)throw new TypeError('Native cipher requires word feedback');
  const entry = { name: 'e' + randomBytes(12).toString('hex'), bytes };
  const settings = { ...FIXED, ...options, packetLayout: options.packetLayout ?? {}, recordCacheLimit: options.recordCacheLimit ?? 256 };
  const joint = jointMaterializer(opaqueWrapperProgram(), [entry], settings);
  joint.plan.batchSpans = true;
  joint.plan.sessionOwnership = true;
  joint.plan.summary = Object.freeze({ ...joint.summary, leanRuntime:options.leanRuntime??false, entryMode: 'private-value', inputBytes: bytes.length, minimumPages: settings.packetLayout.minimumPages ?? 4, sharedHandlers: options.sharedHandlers ?? false, wordFeedback: options.wordFeedback ?? false, nonlinearFeedback: options.nonlinearFeedback ?? false, pageSeedBits: options.nonlinearFeedback ? 32 : 16, pageChain: options.nonlinearFeedback ? 'digest-and-word-state' : 'digest', compressionMode: options.compressionMode ?? 'greedy', sessionOwnership: 'private-token' });
  const program = activateResultLinks(dataProgram(joint.program), {cfg: options.cfgResultLinks ?? false, semanticReceipts:options.semanticReceipts??false});
  const resultLinkProofs = options.cfgResultLinks ? Object.freeze(program.prototypes.flatMap((p, index) => (p.resultLinks ?? []).map(link => Object.freeze({prototype: index + 1, ...link})))) : undefined;
  joint.plan.summary = Object.freeze({...joint.plan.summary, emulationSurface: analyzeEmulationSurface(program), boundPages: options.boundPages ?? false, ...(options.boundPages ? {pageGate:'hmac-sha256-128-full-content',pageSeed:'hmac-sha256-gate-context',childEntry:'hmac-gate-id-parent',childPermit:'single-use-lexical-ticket',childTagBytes:16,childTagTotalBytes:program.prototypes.filter(p=>p.sealKey).length*16,recordContext:'prototype-and-pc'} : {})});
  joint.plan.summary = Object.freeze({ ...joint.plan.summary, transportDirectory: options.compactTransport ? 'rank-u16' : 'offset-u32', transportDirectoryBytes: program.prototypes.length * (options.compactTransport ? 14 : 20), sealedCipher: options.nativeCipher ? 'native-buffer-bit32' : 'portable', cipherCycles: 32 });
  joint.plan.summary = Object.freeze({ ...joint.plan.summary, ...(resultLinkProofs ? {resultLinkProofs} : {}), cfgResultLinks: options.cfgResultLinks ?? false, resultPathReceipts: program.resultPathReceipts, resultLinkCopies: program.stats.resultLinkCopies, resultLinkBranches: program.stats.resultLinkBranches, resultLinkJoins: program.stats.resultLinkJoins, resultLinkMaxHops: program.stats.resultLinkMaxHops, resultBranchConsumers:program.stats.resultBranchConsumers??0,resultIndexConsumers:program.stats.resultIndexConsumers??0,semanticReceipts:options.semanticReceipts??false,resultLinkPairs: program.stats.resultLinkPairs ?? 0, resultLinkOperands: program.stats.resultLinkOperands ?? 0, callableEntry: options.callableEntry ?? false, identityWitness: options.identityWitness ?? false, instructionDirectory: options.keyedDirectory?'transfer-key-descriptors':options.denseMetadata?'buffer-u32':'sparse-tables',keyedDirectory:options.keyedDirectory??false, ...(options.denseMetadata||options.keyedDirectory?{directoryBytes:program.stats.instructions*(options.contextCount??2)*4,offsetTablesAvoided:program.stats.instructions}: {}),...(options.keyedDirectory?{physicalRecords:'shuffled',directoryAuthorization:'instruction-key-prototype-pc-bank'}:{}) });
  const serialized = serializeData(program, {
    contextCount: options.contextCount ?? 2,
    compactRecords: true, batchSpans: true, fastCipher: true,
    sectionTransport: true, activatedConstants: options.activatedConstants ?? false,
    consumerHandlers: options.consumerHandlers ?? false,
    sharedHandlers: options.sharedHandlers ?? false,
    denseMetadata: options.denseMetadata ?? false,
    identityWitness: options.identityWitness ?? false,
    leanRuntime: options.leanRuntime ?? false,
    keyedDirectory: options.keyedDirectory ?? false,
    narrowRecords: options.narrowRecords ?? false,
    compactPrototypeMetadata: options.compactPrototypeMetadata,
    sealedRecords: options.sealedRecords,
    bitPackedRecords: options.bitPackedRecords,
    bitPackedConstants: options.bitPackedConstants,
    bufferLanes: options.bufferLanes,
  });
  joint.plan.summary=Object.freeze({...joint.plan.summary,narrowRecords:options.narrowRecords??false,entropyStreams:options.entropyStreams??false,...(options.narrowRecords?{recordEncoding:'role-width-modular',directoryBytes:dataSchema(serialized).recordStorage.directoryBytes,narrowWordSavedBytes:dataSchema(serialized).recordStorage.narrowWordSavedBytes,directorySavedBytes:dataSchema(serialized).recordStorage.directorySavedBytes}:{})});
  const blob=attachMaterializer(serialized,joint.plan);
  const schema=dataSchema(serialized);
  joint.plan.summary=Object.freeze({...joint.plan.summary,compactPrototypeMetadata:options.compactPrototypeMetadata,prototypeStorage:schema.prototypeStorage,registerAllocation:schema.registerAllocation,sealedRecords:options.sealedRecords,bufferLanes:options.bufferLanes,bitPackedRecords:options.bitPackedRecords,bitPackedConstants:options.bitPackedConstants,activatedConstants:options.activatedConstants,constantStorage:schema.constantStorage,recordPaddingBytes:schema.recordStorage.paddingBytes});
  return buildNilWrapper(blob, {
    ...settings, requireBit32: !!(options.wordFeedback||options.bufferLanes), opaqueChunks: new Map([[entry.name, bytes]]),
    markerComment: options.markerComment ?? leadingMarkerComment(bytes.toString('utf8')),
  });
}

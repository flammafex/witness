// `@witness/sdk` public entry point.
//
// Re-exports the client surface, error hierarchy, WebSocket subscription, the
// generated wire types, and the local verifier (`WitnessVerifier`) plus the
// explicit `decodeAttestationSignatures` discriminating decoder (§3.5).

export { WitnessClient } from './client.js';
export type { PollConfig, FreebirdTokenInput } from './client.js';

export {
  WitnessError,
  TransportError,
  HttpStatusError,
  NotFoundError,
  JobFailedError,
  ConfirmationTimeoutError,
  DecodeError,
  VerificationError,
  AuthRequiredError,
} from './errors.js';
export type { WitnessErrorCode, VerificationFailureReason } from './errors.js';

export { subscribeEvents } from './ws.js';
export type { SubscribeOptions, EventsSubscription } from './ws.js';

export { WitnessVerifier, decodeAttestationSignatures, decodeHex } from './verify/index.js';
export type { DecodedAttestationSignatures } from './verify/index.js';

export { loadWitnessCore } from './wasm/loader.js';
export type { WitnessCoreModule, WasmResult } from './wasm/loader.js';

export * from './types.generated.js';
